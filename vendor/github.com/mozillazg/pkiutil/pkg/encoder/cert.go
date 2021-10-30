package encoder

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func PemEncodeCert(cert *x509.Certificate) ([]byte, error) {
	return PemEncodeRawCert(cert.Raw)
}

func PemEncodeRawCert(cert []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	if err := pem.Encode(buf, block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func PemEncodeRawCerts(certs [][]byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	for _, certBytes := range certs {
		data, err := PemEncodeRawCert(certBytes)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
	}
	return buf.Bytes(), nil
}

func PemEncodePrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	return PemEncodeRawPrivateKey(x509.MarshalPKCS1PrivateKey(key))
}

func PemEncodeRawPrivateKey(key []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: key,
	}
	if err := pem.Encode(buf, block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
