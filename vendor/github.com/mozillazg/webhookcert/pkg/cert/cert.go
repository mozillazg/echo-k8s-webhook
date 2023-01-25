package cert

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	errors "golang.org/x/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	klog "k8s.io/klog/v2"
)

type CertOption struct {
	// CAName will be used as CommonName of CA cert
	CAName string
	// Organizations for certs
	Organizations []string
	// Hosts for server cert
	Hosts []string
	// CommonName for server cert
	CommonName string
	// RSA key size, default: 2048
	RSAKeySize int
	// cert dir to mount secret
	CertDir string
	// cert will be expired after this duration, default: 100 years
	CertValidityDuration time.Duration
	// Deprecated: use Organizations instead
	CAOrganizations []string
	// Deprecated: user Hosts instead
	DNSNames []string

	SecretInfo SecretInfo
}

type WebhookCert struct {
	certOpt CertOption

	certmanager    *certManager
	webhookmanager *webhookManager
	checkerClient  checkerClientInterface
}

type checkerClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewWebhookCert(certOpt CertOption, webhooks []WebhookInfo, kubeclient kubernetes.Interface, dyclient dynamic.Interface) *WebhookCert {
	return &WebhookCert{
		certOpt: certOpt,
		certmanager: &certManager{
			secretInfo:   certOpt.SecretInfo,
			certOpt:      certOpt,
			secretClient: kubeclient.CoreV1().Secrets(certOpt.SecretInfo.Namespace),
		},
		webhookmanager: newWebhookManager(webhooks, dyclient),
		checkerClient: &http.Client{Transport: &http.Transport{
			// TODO: use ca from secret
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}},
	}
}

func (w *WebhookCert) EnsureCertReady(ctx context.Context) error {
	if err := w.ensureCert(ctx); err != nil {
		return errors.Errorf(": %w", err)
	}
	klog.Info("ensure cert success")
	if err := w.ensureCertsMounted(ctx); err != nil {
		return errors.Errorf(": %w", err)
	}
	klog.Info("ensure cert mounted success")
	return nil
}

func (w *WebhookCert) WatchAndEnsureWebhooksCA(ctx context.Context) error {
	events := make(chan watch.Event)
	watchTimeout := time.Hour * 23
	if os.Getenv("WEBHOOKCERT_DEBUG_WATCH") == "true" {
		watchTimeout = time.Minute * 15
	}

	for _, info := range w.webhookmanager.webhooks {
		info := info
		go func(info WebhookInfo) {
			wait.JitterUntilWithContext(ctx, func(_ context.Context) {
				timeout := wait.Jitter(watchTimeout, 0.1)
				err := w.webhookmanager.watchChanges(ctx, events, info, timeout)
				if err != nil {
					if apierrors.IsNotFound(err) {
						klog.Warningf("webhook %s is not found, delay watch", info.Name)
						time.Sleep(wait.Jitter(time.Hour*24, 0.1))
						return
					}
					klog.Errorf("watch webhook changes failed: %+v", err)
				}
			}, time.Minute, 5.0, true)
		}(info)
	}

	for {
		select {
		case e := <-events:
			if e.Type == watch.Added || e.Type == watch.Modified {
				if err := w.ensureCAWhenWebhookChange(ctx); err != nil {
					klog.Errorf("ensure webhook ca failed: %+v", err)
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (w *WebhookCert) ensureCAWhenWebhookChange(ctx context.Context) error {
	if err := w.ensureCert(ctx); err != nil {
		return errors.Errorf(": %w", err)
	}
	return nil
}

func (w *WebhookCert) CheckServerStartedWithTimeout(addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	return w.CheckServerStarted(ctx, addr)
}

func (w *WebhookCert) CheckServerStarted(ctx context.Context, addr string) error {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	d := &tls.Dialer{Config: config}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.Errorf("webhook server is not reachable: %w", err)
	}

	if err := conn.Close(); err != nil {
		return errors.Errorf("webhook server is not reachable: closing connection: %w", err)
	}

	return nil
}

func (w *WebhookCert) CheckServerCertValidWithTimeout(addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	return w.CheckServerCertValid(ctx, addr)
}

func (w *WebhookCert) CheckServerCertValid(ctx context.Context, addr string) error {
	url := addr
	if !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("https://%s", url)
	}
	req, err := http.NewRequest(http.MethodGet, addr, nil)
	if err != nil {
		return errors.Errorf("init request: %w", err)
	}
	req = req.WithContext(ctx)
	resp, err := w.checkerClient.Do(req)
	if err != nil {
		return errors.Errorf("connect webhook server: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return errors.New("webhook server does not serve TLS certificate")
	}
	respCerts := resp.TLS.PeerCertificates
	currentCerts, err := tls.LoadX509KeyPair(w.certOpt.getServerCertPath(), w.certOpt.getServerKeyPath())
	if err != nil {
		return errors.Errorf("load server cert from %s: %w", w.certOpt.CertDir, err)
	}
	if len(respCerts) != len(currentCerts.Certificate) {
		return errors.Errorf("certificate chain mismatch: %d != %d", len(respCerts), len(currentCerts.Certificate))
	}
	for i, cert := range respCerts {
		if !bytes.Equal(cert.Raw, currentCerts.Certificate[i]) {
			return errors.New("certificate chain mismatch")
		}
	}
	return nil
}

func (w *WebhookCert) ensureCert(ctx context.Context) error {
	secret, err := w.certmanager.ensureSecret(ctx)
	if err != nil {
		return errors.Errorf("ensure secret: %w", err)
	}
	klog.Info("ensure secret success")
	ka, err := w.certmanager.buildArtifactsFromSecret(secret)
	if err != nil {
		return errors.Errorf("parse secret: %w", err)
	}
	err = w.webhookmanager.ensureCA(ctx, ka.certPEM)
	if err == nil {
		klog.Info("ensure webhook ca config success")
	}
	return err
}

func (w *WebhookCert) ensureCertsMounted(ctx context.Context) error {
	checkFn := func() (bool, error) {
		certFile := w.certOpt.CertDir + "/" + w.certOpt.SecretInfo.getCertName()
		_, err := os.Stat(certFile)
		if err == nil {
			return true, nil
		}
		return false, nil
	}
	if err := wait.ExponentialBackoffWithContext(ctx, wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   1,
		Steps:    10,
	}, checkFn); err != nil {
		return errors.Errorf("max retries for checking certs existence: %w", err)
	}

	klog.Infof("certs are ready in %s", w.certOpt.CertDir)
	return nil
}

func (c CertOption) getCertValidityDuration() time.Duration {
	if c.CertValidityDuration == 0 {
		return certValidityDuration
	}
	return c.CertValidityDuration
}

func (c CertOption) getHots() []string {
	hosts := []string{}
	hosts = append(hosts, c.Hosts...)
	hosts = append(hosts, c.DNSNames...)
	return hosts
}

func (c CertOption) getOrganizations() []string {
	orgs := []string{}
	orgs = append(orgs, c.Organizations...)
	orgs = append(orgs, c.CAOrganizations...)
	return orgs
}

func (c CertOption) getRSAKeySize() int {
	if c.RSAKeySize >= 2048 {
		return c.RSAKeySize
	}
	return rsaKeySize
}

func (c CertOption) getServerCertPath() string {
	return path.Join(c.CertDir, c.SecretInfo.getCertName())
}

func (c CertOption) getServerKeyPath() string {
	return path.Join(c.CertDir, c.SecretInfo.getKeyName())
}
