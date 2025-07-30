package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"time"

	hqgoerrors "github.com/hueristiq/hq-go-errors"
)

// CertificateAuthority represents a Certificate Authority (CA) for generating and signing TLS certificates.
//
// It holds a CA certificate, its private key, a private key for TLS certificates, and a subject key identifier.
// The struct provides methods to generate TLS configurations and certificates dynamically based on
// Server Name Indication (SNI) hostnames.
//
// Fields:
//   - _CACertificate (*x509.Certificate): The X.509 CA certificate used to sign TLS certificates.
//   - _CAPrivateKey (*rsa.PrivateKey): The RSA private key corresponding to the CA certificate.
//   - _TLSPrivateKey (*rsa.PrivateKey): The RSA private key used for generated TLS certificates.
//   - _SubjectKeyID ([]byte): The subject key identifier for the TLS private key, as per RFC 5280.
type CertificateAuthority struct {
	_CACertificate *x509.Certificate
	_CAPrivateKey  *rsa.PrivateKey
	_TLSPrivateKey *rsa.PrivateKey
	_SubjectKeyID  []byte
}

// GetCACertificate returns the CA certificate stored in the CertificateAuthority.
//
// Returns:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 CA certificate.
func (CA *CertificateAuthority) GetCACertificate() (CACertificate *x509.Certificate) {
	CACertificate = CA._CACertificate

	return
}

// NewTLSConfig creates a TLS configuration for use in a TLS server.
//
// The configuration includes a dynamic certificate generation function based on
// Server Name Indication (SNI) and sets a minimum TLS version of TLS 1.2.
// It also specifies supported protocols for Application-Layer Protocol Negotiation (ALPN).
// Errors during certificate generation are handled within the GetCertificate callback.
//
// Returns:
//   - cfg (*tls.Config): A pointer to a tls.Config with a dynamic certificate generation function.
func (CA *CertificateAuthority) NewTLSConfig() (cfg *tls.Config) {
	cfg = &tls.Config{
		GetCertificate: CA.getTLSCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.0", "http/1.1", "http/2.0"},
	}

	return
}

// getTLSCertificateFunc returns a function to generate TLS certificates based on SNI.
//
// The returned function is used as the GetCertificate callback in a tls.Config.
// It generates a new TLS certificate for the provided server name (from SNI) or
// returns an error if the server name is missing. Errors are wrapped with context
// and metadata using hq-go-errors.
//
// Returns:
//   - (func(*tls.ClientHelloInfo) (*tls.Certificate, error)): A function that takes a tls.ClientHelloInfo and returns a tls.Certificate and an error.
//     The error includes stack trace and metadata if certificate generation fails or SNI is missing.
func (CA *CertificateAuthority) getTLSCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
		if hello.ServerName == "" {
			err = hqgoerrors.New("missing server name (SNI)")

			return
		}

		host := normalizeHost(hello.ServerName)

		certificate, err = CA.generateTLSCertificate([]string{host})
		if err != nil {
			err = hqgoerrors.Wrap(err, "failed to generate TLS certificate")

			return
		}

		return
	}
}

// generateTLSCertificate generates a new TLS certificate signed by the CA for the specified hostname.
//
// The certificate is valid for 48 hours (from 24 hours in the past to 24 hours in the future),
// includes a random serial number, and is configured for server authentication. It supports
// either an IP address or DNS name based on the hostname. The certificate is signed using the
// CA's private key and includes the CA certificate in the certificate chain. Errors are wrapped
// with context and metadata using hq-go-errors.
//
// Parameters:
//   - hosts ([]string): The server name (DNS name or IP address) for the certificate.
//
// Returns:
//   - certificate (*tls.Certificate): A pointer to a tls.Certificate containing the generated certificate,
//     CA certificate, private key, and parsed leaf certificate.
//   - err (error): An error with stack trace and metadata if serial number generation, certificate creation,
//     or parsing fails; otherwise, nil.
func (CA *CertificateAuthority) generateTLSCertificate(hosts []string) (certificate *tls.Certificate, err error) {
	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate serial number for TLS certificate")

		return
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Hueristiq"},
		},
		SubjectKeyId:          CA._SubjectKeyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
	}

	for _, host := range hosts {
		if IP := net.ParseIP(host); IP != nil {
			template.IPAddresses = append(template.IPAddresses, IP)
		} else if email, err := mail.ParseAddress(host); err == nil && email.Address == host {
			template.EmailAddresses = append(template.EmailAddresses, host)
		} else if uriName, err := url.Parse(host); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			template.URIs = append(template.URIs, uriName)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	var certificateInBytes []byte

	certificateInBytes, err = x509.CreateCertificate(rand.Reader, template, CA._CACertificate, CA._TLSPrivateKey.Public(), CA._CAPrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to create TLS certificate")

		return
	}

	var leaf *x509.Certificate

	leaf, err = x509.ParseCertificate(certificateInBytes)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to parse TLS certificate")

		return
	}

	certificate = &tls.Certificate{
		Certificate: [][]byte{certificateInBytes, CA._CACertificate.Raw},
		PrivateKey:  CA._TLSPrivateKey,
		Leaf:        leaf,
	}

	return
}

// New initializes a new CertificateAuthority with the provided CA certificate and private key.
//
// It verifies that the certificate is configured as a CA and has the necessary key usage for
// certificate signing. A new 2048-bit RSA private key is generated for TLS certificates, and a
// subject key identifier is computed for it. Errors are wrapped with context and metadata using
// hq-go-errors.
//
// Parameters:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the RSA private key corresponding to the CA certificate.
//
// Returns:
//   - CA (*CertificateAuthority): A pointer to the initialized CertificateAuthority.
//   - err (error): An error with stack trace and metadata if the CA certificate is invalid, key generation
//     fails, or subject key ID generation fails; otherwise, nil.
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

	pubKey := TLSPrivateKey.Public()

	var SKI []byte

	SKI, err = generateSubjectKeyID(pubKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate subject key ID for TLS private key")

		return
	}

	CA = &CertificateAuthority{
		_CACertificate: CACertificate,
		_CAPrivateKey:  CAPrivateKey,
		_TLSPrivateKey: TLSPrivateKey,
		_SubjectKeyID:  SKI,
	}

	return
}

func normalizeHost(unnormalized string) (normalized string) {
	normalized = unnormalized

	if host, _, err := net.SplitHostPort(unnormalized); err == nil {
		normalized = host

		return
	}

	return
}
