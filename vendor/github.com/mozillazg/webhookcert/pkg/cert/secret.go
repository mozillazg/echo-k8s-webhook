package cert

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/mozillazg/pkiutil/pkg/decoder"
	"github.com/mozillazg/pkiutil/pkg/encoder"
	certgen "github.com/mozillazg/pkiutil/pkg/generator"
	errors "golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	klog "k8s.io/klog/v2"
)

const (
	certName             = "tls.crt"
	keyName              = "tls.key"
	caCertName           = "ca.crt"
	caKeyName            = "ca.key"
	certValidityDuration = time.Hour * 24 * 365 * 100 // 100 years
	rsaKeySize           = 2048
)

type keyPairArtifacts struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

type SecretInfo struct {
	Name      string
	Namespace string

	caCertName string
	caKeyName  string
	certName   string
	keyName    string

	// dont save ca key to secret?
	dontSaveCaKey bool
}

type certManager struct {
	secretInfo   SecretInfo
	certOpt      CertOption
	secretClient secretInterface
}

type secretInterface interface {
	Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error)
}

func (c *certManager) ensureSecret(ctx context.Context) (*corev1.Secret, error) {
	var secret *corev1.Secret
	var err error

	retry.OnError(retry.DefaultBackoff, func(err error) bool {
		return err != nil
	}, func() error {
		secret, err = c.ensureSecretWithoutRetry(ctx)
		return err
	})

	return secret, err
}

func (c *certManager) ensureSecretWithoutRetry(ctx context.Context) (*corev1.Secret, error) {
	client := c.secretClient
	name := c.secretInfo.Name
	secret, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, errors.Errorf("get secret %s: %w", name, err)
		}
		klog.Warningf("secret %s is not found, will create secret", name)
		newSecret, err := c.newSecret()
		if err != nil {
			return nil, errors.Errorf("new secret: %w", err)
		}
		return client.Create(ctx, newSecret, metav1.CreateOptions{})
	}

	checkNotAfter := time.Now().Add(-wait.Jitter(time.Hour*24*7, 0.5))
	if err := c.certSecretIsValid(secret, time.Now(), checkNotAfter); err != nil {
		klog.Warningf("parse cert from secret %s failed, will update exist secret: %s", name, err)
		newSecret, err := c.newSecret()
		if err != nil {
			return nil, errors.Errorf("new secret: %w", err)
		}
		secret.Data = newSecret.Data
		return client.Update(ctx, secret, metav1.UpdateOptions{})
	}
	klog.Infof("use exist secret %s", name)
	return secret, nil
}

func (c *certManager) newSecret() (*corev1.Secret, error) {
	var caArtifacts *keyPairArtifacts
	now := time.Now()
	begin := now.Add(-1 * time.Hour)
	end := now.Add(c.certOpt.getCertValidityDuration())
	caArtifacts, err := c.createCACert(begin, end)
	if err != nil {
		return nil, errors.Errorf("create ca cert: %w", err)
	}
	cert, key, err := c.createCertPEM(caArtifacts, begin, end)
	if err != nil {
		return nil, errors.Errorf("create cert: %w", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.secretInfo.Name,
			Namespace: c.secretInfo.Namespace,
		},
		Data: map[string][]byte{},
	}
	c.populateSecret(cert, key, caArtifacts, secret)
	return secret, nil
}

func (c *certManager) populateSecret(cert, key []byte, caArtifacts *keyPairArtifacts, secret *corev1.Secret) {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[c.secretInfo.getCACertName()] = caArtifacts.certPEM
	if !c.secretInfo.dontSaveCaKey {
		secret.Data[c.secretInfo.getCAKeyName()] = caArtifacts.keyPEM
	}
	secret.Data[c.secretInfo.getCertName()] = cert
	secret.Data[c.secretInfo.getKeyName()] = key
}

func (c *certManager) buildArtifactsFromSecret(secret *corev1.Secret) (*keyPairArtifacts, error) {
	caPem, ok := secret.Data[c.secretInfo.getCACertName()]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caCertName))
	}
	caCert, _, err := decoder.DecodePemCert(caPem)
	if err != nil {
		return nil, errors.Errorf("while parsing CA cert: %w", err)
	}
	kp := &keyPairArtifacts{
		cert:    caCert,
		certPEM: caPem,
	}

	if !c.secretInfo.dontSaveCaKey {
		keyPem, ok := secret.Data[c.secretInfo.getCAKeyName()]
		if !ok {
			return nil, errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caKeyName))
		}
		key, _, err := decoder.DecodePemPrivateKey(keyPem)
		if err != nil {
			return nil, errors.Errorf("while parsing CA key: %w", err)
		}
		kp.keyPEM = keyPem
		kp.key = key
	}
	return kp, nil
}

func (c *certManager) certSecretIsValid(secret *corev1.Secret, now, notAfter time.Time) error {
	ca, err := c.buildArtifactsFromSecret(secret)
	if err != nil {
		return err
	}
	caCert := ca.cert
	serverPem, ok := secret.Data[c.secretInfo.getCertName()]
	if !ok {
		return errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caCertName))
	}
	serverKey, ok := secret.Data[c.secretInfo.getKeyName()]
	if !ok {
		return errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caCertName))
	}
	serverCert, _, err := decoder.DecodePemCert(serverPem)
	if err != nil {
		return errors.Errorf("while parsing server cert: %w", err)
	}
	if _, _, err := decoder.DecodePemPrivateKey(serverKey); err != nil {
		return errors.Errorf("while parsing server key: %w", err)
	}

	if err := certIsValid(caCert, now, notAfter); err != nil {
		return err
	}
	if err := certIsValid(serverCert, now, notAfter); err != nil {
		return err
	}

	return nil
}

func (c *certManager) createCACert(begin, end time.Time) (*keyPairArtifacts, error) {
	cert, key, err := certgen.GenCACert(certgen.CertOption{
		CommonName:    c.certOpt.CAName,
		Organizations: c.certOpt.getOrganizations(),
		NotBefore:     begin,
		NotAfter:      end,
		RSAKeySize:    c.certOpt.getRSAKeySize(),
	})
	if err != nil {
		return nil, errors.Errorf("generating cert: %w", err)
	}
	certPem, err := encoder.PemEncodeCert(cert)
	if err != nil {
		return nil, errors.Errorf("encoding PEM: %w", err)
	}
	keyPem, err := encoder.PemEncodePrivateKey(key)
	if err != nil {
		return nil, errors.Errorf("encoding PEM: %w", err)
	}
	return &keyPairArtifacts{cert: cert, key: key, certPEM: certPem, keyPEM: keyPem}, nil
}

func (c *certManager) createCertPEM(ca *keyPairArtifacts, begin, end time.Time) ([]byte, []byte, error) {
	cert, key, err := certgen.GenServerCert(certgen.CertOption{
		CommonName:    c.certOpt.CommonName,
		Organizations: c.certOpt.getOrganizations(),
		Hosts:         c.certOpt.getHots(),
		NotBefore:     begin,
		NotAfter:      end,
		RSAKeySize:    c.certOpt.getRSAKeySize(),
		ParentCert:    ca.cert,
		ParentKey:     ca.key,
	})
	if err != nil {
		return nil, nil, errors.Errorf("generating cert: %w", err)
	}
	certPem, err := encoder.PemEncodeCert(cert)
	if err != nil {
		return nil, nil, errors.Errorf("encoding PEM: %w", err)
	}
	keyPem, err := encoder.PemEncodePrivateKey(key)
	if err != nil {
		return nil, nil, errors.Errorf("encoding PEM: %w", err)
	}
	return certPem, keyPem, nil
}

func (s SecretInfo) getCACertName() string {
	if s.caCertName != "" {
		return s.caCertName
	}
	return caCertName
}

func (s SecretInfo) getCAKeyName() string {
	if s.caKeyName != "" {
		return s.caKeyName
	}
	return caKeyName
}

func (s SecretInfo) getCertName() string {
	if s.certName != "" {
		return s.certName
	}
	return certName
}

func (s SecretInfo) getKeyName() string {
	if s.keyName != "" {
		return s.keyName
	}
	return keyName
}

func mergeCAPemCerts(pemCerts []byte, newPemCerts []byte) (changed bool, certs []byte) {
	if bytes.Contains(pemCerts, bytes.TrimSpace(newPemCerts)) {
		return false, pemCerts
	}

	var newCerts tls.Certificate
	oldCerts := decodePEMCerts(pemCerts)
	var oldCertBytes []byte
	// only merge one old ca
	if len(oldCerts.Certificate) > 0 {
		oldCertBytes = oldCerts.Certificate[0]
	}
	caCerts := decodePEMCerts(newPemCerts)

	// new ca then old ca
	newCerts.Certificate = append(newCerts.Certificate, caCerts.Certificate...)
	if len(oldCertBytes) > 0 {
		newCerts.Certificate = append(newCerts.Certificate, oldCertBytes)
	}

	pemBytes, _ := encodePEMCerts(&newCerts)
	return true, pemBytes
}

func decodePEMCerts(pemCerts []byte) *tls.Certificate {
	var certs tls.Certificate
	cs, err := decoder.DecodePemCerts(pemCerts)
	if err == nil {
		for _, c := range cs {
			certs.Certificate = append(certs.Certificate, c.Raw)
		}
	}
	return &certs
}

func encodePEMCerts(certs *tls.Certificate) ([]byte, error) {
	data, err := encoder.PemEncodeRawCerts(certs.Certificate)
	if err != nil {
		return nil, errors.Errorf("encoding cert: %w", err)
	}
	return data, nil
}

func certIsValid(c *x509.Certificate, now, notAfter time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	if notAfter.IsZero() {
		notAfter = time.Now()
	}
	if now.Before(c.NotBefore) {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.Expired,
			Detail: fmt.Sprintf("current time %s is before %s", now.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339)),
		}
	} else if notAfter.After(c.NotAfter) {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.Expired,
			Detail: fmt.Sprintf("not after time %s is after %s", notAfter.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
		}
	}
	return nil
}
