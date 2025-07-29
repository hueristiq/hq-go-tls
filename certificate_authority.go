package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	hqgoerrors "github.com/hueristiq/hq-go-errors"
)

type CertificateAuthority struct {
	_CACertificate *x509.Certificate
	_CAPrivateKey  *rsa.PrivateKey
	_TLSPrivateKey *rsa.PrivateKey
	_SubjectKeyID  []byte
}

func (ca *CertificateAuthority) NewTLSConfig() (cfg *tls.Config) {
	cfg = &tls.Config{
		GetCertificate: ca.getTLSCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.0", "http/1.1", "http/2.0"},
	}

	return
}

func (ca *CertificateAuthority) getTLSCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
		if clientHello.ServerName == "" {
			err = hqgoerrors.New("missing server name (SNI)")

			return
		}

		certificate, err = ca.generateTLSCertificate(clientHello.ServerName)

		return
	}
}

func (ca *CertificateAuthority) generateTLSCertificate(hostname string) (certificate *tls.Certificate, err error) {
	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate serial number")

		return
	}

	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Hueristiq"},
		},
		SubjectKeyId:          ca._SubjectKeyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	var certificateInBytes []byte

	certificateInBytes, err = x509.CreateCertificate(rand.Reader, template, ca._CACertificate, ca._TLSPrivateKey.Public(), ca._CAPrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to create certificate")

		return
	}

	var leaf *x509.Certificate

	leaf, err = x509.ParseCertificate(certificateInBytes)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to parse certificate")

		return
	}

	certificate = &tls.Certificate{
		Certificate: [][]byte{certificateInBytes, ca._CACertificate.Raw},
		PrivateKey:  ca._TLSPrivateKey,
		Leaf:        leaf,
	}

	return
}

func New(CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey) (CA *CertificateAuthority, err error) {
	if !CACertificate.IsCA {
		err = hqgoerrors.New("certificate is not configured as CA")

		return
	}

	if (CACertificate.KeyUsage & x509.KeyUsageCertSign) == 0 {
		err = hqgoerrors.New("CA certificate missing certSign key usage")

		return
	}

	var TLSPrivateKey *rsa.PrivateKey

	TLSPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate TLS private key")

		return
	}

	publicKey := TLSPrivateKey.Public()

	var subjectKeyID []byte

	subjectKeyID, err = generateSubjectKeyID(publicKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate subject key ID")

		return
	}

	CA = &CertificateAuthority{
		_CACertificate: CACertificate,
		_CAPrivateKey:  CAPrivateKey,
		_TLSPrivateKey: TLSPrivateKey,
		_SubjectKeyID:  subjectKeyID,
	}

	return
}
