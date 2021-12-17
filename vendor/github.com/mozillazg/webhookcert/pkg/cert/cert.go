package cert

import (
	"context"
	"os"
	"time"

	errors "golang.org/x/xerrors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	klog "k8s.io/klog/v2"
)

type CertOption struct {
	CAName          string
	CAOrganizations []string
	Hosts           []string
	// Deprecated: user Hosts instead
	DNSNames             []string
	CommonName           string
	CertDir              string
	CertValidityDuration time.Duration

	SecretInfo SecretInfo
}

type WebhookCert struct {
	certOpt CertOption

	certmanager    *certManager
	webhookmanager *webhookManager
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
	hosts = append(hosts, c.DNSNames...)
	hosts = append(hosts, c.Hosts...)
	return hosts
}
