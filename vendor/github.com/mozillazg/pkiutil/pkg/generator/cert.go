package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	defaultCertValidityDuration = time.Hour * 24 * 30 * 3
	defaultRSAKeySize           = 2048
)

type CertOption struct {
	CommonName    string
	Organizations []string
	Hosts         []string
	NotBefore     time.Time
	NotAfter      time.Time

	RSAKeySize int
	PrivateKey *rsa.PrivateKey

	ParentCert *x509.Certificate
	ParentKey  *rsa.PrivateKey

	ExtraSubject    pkix.Name
	ExtraExtensions []pkix.Extension
}

type certOption struct {
	CertOption

	isCA     bool
	isServer bool
	isClient bool
}

func GenCACert(option CertOption) (*x509.Certificate, *rsa.PrivateKey, error) {
	opt := certOption{
		CertOption: option,
		isCA:       true,
		isServer:   false,
		isClient:   false,
	}
	return genCert(opt)
}

func GenServerCert(option CertOption) (*x509.Certificate, *rsa.PrivateKey, error) {
	opt := certOption{
		CertOption: option,
		isCA:       false,
		isServer:   true,
		isClient:   false,
	}
	return genCert(opt)
}

func GenClientCert(option CertOption) (*x509.Certificate, *rsa.PrivateKey, error) {
	opt := certOption{
		CertOption: option,
		isCA:       false,
		isServer:   false,
		isClient:   true,
	}
	return genCert(opt)
}

func genCert(option certOption) (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNum, err := genSerialNum()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serialNum,
		Subject:               option.ExtraSubject,
		NotBefore:             option.getNotBefore(),
		NotAfter:              option.getNotAfter(),
		BasicConstraintsValid: true,
		ExtraExtensions:       option.ExtraExtensions,
	}
	if option.CommonName != "" {
		template.Subject.CommonName = option.CommonName
	}
	if len(option.Organizations) != 0 {
		template.Subject.Organization = option.Organizations
	}

	for _, h := range option.Hosts {
		h := strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, h)
	}

	if option.isCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign
		template.IsCA = true
	}
	if option.isServer {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IsCA = false
	}
	if option.isClient {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.IsCA = false
	}

	privateKey := option.PrivateKey
	if privateKey == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, option.getRSAKeySize())
		if err != nil {
			return nil, nil, err
		}
	}
	publicKey := privateKey.Public()

	parentCert := option.ParentCert
	if parentCert == nil {
		parentCert = template
	}
	parentKey := option.ParentKey
	if parentKey == nil {
		parentKey = privateKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, publicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func genSerialNum() (*big.Int, error) {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number failed: %s", err)
	}
	return serialNum, nil
}

func (o CertOption) getNotBefore() time.Time {
	if !o.NotBefore.IsZero() {
		return o.NotBefore
	}
	return time.Now().Add(-time.Hour)
}

func (o CertOption) getNotAfter() time.Time {
	if !o.NotAfter.IsZero() {
		return o.NotAfter
	}
	notBefore := o.getNotBefore()
	return notBefore.Add(defaultCertValidityDuration)
}

func (o CertOption) getRSAKeySize() int {
	if o.RSAKeySize > 0 {
		return o.RSAKeySize
	}
	return defaultRSAKeySize
}
