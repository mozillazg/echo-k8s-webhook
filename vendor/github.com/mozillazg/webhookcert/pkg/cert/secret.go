package cert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	errors "golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	klog "k8s.io/klog/v2"
)

const (
	certName             = "tls.crt"
	keyName              = "tls.key"
	caCertName           = "ca.crt"
	caKeyName            = "ca.key"
	certValidityDuration = time.Hour * 24 * 365 * 10
)

type KeyPairArtifacts struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

type SecretInfo struct {
	Name       string
	Namespace  string
	caCertName string
	caKeyName  string
	certName   string
	keyName    string
}

type CertManager struct {
	secretInfo    SecretInfo
	certOpt       CertOption
	secretsGetter v1.SecretsGetter
}

func (c *CertManager) ensureSecret(ctx context.Context) (*corev1.Secret, error) {
	secret, err := c.ensureSecretWithoutRetry(ctx)
	if err != nil {
		if apierrors.IsAlreadyExists(err) || apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			return c.ensureSecretWithoutRetry(ctx)
		}
	}
	return secret, err
}

func (c *CertManager) ensureSecretWithoutRetry(ctx context.Context) (*corev1.Secret, error) {
	client := c.secretsGetter.Secrets(c.secretInfo.Namespace)
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
	_, err = c.buildArtifactsFromSecret(secret)
	if err != nil {
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

func (c *CertManager) newSecret() (*corev1.Secret, error) {
	var caArtifacts *KeyPairArtifacts
	now := time.Now()
	begin := now.Add(-1 * time.Hour)
	end := now.Add(c.certOpt.GetCertValidityDuration())
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

func (c *CertManager) populateSecret(cert, key []byte, caArtifacts *KeyPairArtifacts, secret *corev1.Secret) {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[c.secretInfo.getCACertName()] = caArtifacts.CertPEM
	secret.Data[c.secretInfo.getCAKeyName()] = caArtifacts.KeyPEM
	secret.Data[c.secretInfo.getCertName()] = cert
	secret.Data[c.secretInfo.getKeyName()] = key
}

func (c *CertManager) buildArtifactsFromSecret(secret *corev1.Secret) (*KeyPairArtifacts, error) {
	caPem, ok := secret.Data[c.secretInfo.getCACertName()]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caCertName))
	}
	keyPem, ok := secret.Data[c.secretInfo.getCAKeyName()]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Cert secret is not well-formed, missing %s", c.secretInfo.caKeyName))
	}
	caDer, _ := pem.Decode(caPem)
	if caDer == nil {
		return nil, errors.New("bad CA cert")
	}
	caCert, err := x509.ParseCertificate(caDer.Bytes)
	if err != nil {
		return nil, errors.Errorf("while parsing CA cert: %w", err)
	}
	keyDer, _ := pem.Decode(keyPem)
	if keyDer == nil {
		return nil, errors.New("bad CA cert")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDer.Bytes)
	if err != nil {
		return nil, errors.Errorf("while parsing CA key: %w", err)
	}
	return &KeyPairArtifacts{
		Cert:    caCert,
		CertPEM: caPem,
		KeyPEM:  keyPem,
		Key:     key,
	}, nil
}

func (c *CertManager) createCACert(begin, end time.Time) (*KeyPairArtifacts, error) {
	templ := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   c.certOpt.CAName,
			Organization: c.certOpt.CAOrganizations,
		},
		DNSNames:              c.certOpt.DNSNames,
		NotBefore:             begin,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Errorf("generating key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, templ, templ, key.Public(), key)
	if err != nil {
		return nil, errors.Errorf("creating certificate: %w", err)
	}
	certPEM, keyPEM, err := pemEncode(der, key)
	if err != nil {
		return nil, errors.Errorf("encoding PEM: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Errorf("parsing certificate: %w", err)
	}

	return &KeyPairArtifacts{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (c *CertManager) createCertPEM(ca *KeyPairArtifacts, begin, end time.Time) ([]byte, []byte, error) {
	templ := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: c.certOpt.CommonName,
		},
		DNSNames:              c.certOpt.DNSNames,
		NotBefore:             begin,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.Errorf("generating key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, templ, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, errors.Errorf("creating certificate: %w", err)
	}
	certPEM, keyPEM, err := pemEncode(der, key)
	if err != nil {
		return nil, nil, errors.Errorf("encoding PEM: %w", err)
	}
	return certPEM, keyPEM, nil
}

func pemEncode(certificateDER []byte, key *rsa.PrivateKey) ([]byte, []byte, error) {
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}); err != nil {
		return nil, nil, errors.Errorf("encoding cert: %w", err)
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, nil, errors.Errorf("encoding key: %w", err)
	}
	return certBuf.Bytes(), keyBuf.Bytes(), nil
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

func mergeCAPemCerts(pemCerts []byte, newPemCerts []byte) (bool, []byte) {
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
	newCerts.Certificate = append(newCerts.Certificate, oldCertBytes)

	pemBytes, _ := encodePEMCerts(&newCerts)
	return true, pemBytes
}

func decodePEMCerts(pemCerts []byte) *tls.Certificate {
	var certs tls.Certificate
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		if _, err := x509.ParseCertificate(certBytes); err != nil {
			continue
		}
		certs.Certificate = append(certs.Certificate, certBytes)
	}

	return &certs
}

func encodePEMCerts(certs *tls.Certificate) ([]byte, error) {
	certBuf := &bytes.Buffer{}
	for _, certBytes := range certs.Certificate {
		if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return nil, errors.Errorf("encoding cert: %w", err)
		}
	}
	return certBuf.Bytes(), nil
}
