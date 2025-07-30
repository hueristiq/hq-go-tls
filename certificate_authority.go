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
// It encapsulates a CA certificate and its private key, providing methods to generate TLS configurations
// and certificates dynamically based on Server Name Indication (SNI) hostnames.
//
// Fields:
//   - _CACertificate (*x509.Certificate): The X.509 CA certificate used to sign TLS certificates.
//   - _CAPrivateKey (*rsa.PrivateKey): The RSA private key corresponding to the CA certificate.
type CertificateAuthority struct {
	_CACertificate *x509.Certificate
	_CAPrivateKey  *rsa.PrivateKey
}

// GenerateTLSCertificate generates a new X.509 TLS certificate and its corresponding RSA private key.
//
// This function creates a 2048-bit RSA private key and a TLS certificate signed by the CA, based on the
// provided configuration options and hostnames. The certificate includes a random serial number, a subject
// key identifier (SKI), and supports key encipherment and digital signatures. Hostnames are parsed to
// determine if they represent IP addresses, email addresses, URIs, or DNS names, and are added to the
// appropriate certificate fields. Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - hosts ([]string): A slice of hostnames (e.g., DNS names, IPs, emails, or URIs) to include in the certificate.
//   - TLSCertificatePrivateKeyOptionFuncs (...TLSCertificatePrivateKeyOptionFunc): A variadic list of TLSCertificatePrivateKeyOptionFunc functions
//     to configure the certificate's properties (e.g., CommonName, Organization, ValidFrom, ValidFor).
//
// Returns:
//   - TLSCertificate (*x509.Certificate): A pointer to the generated X.509 TLS certificate.
//   - TLSPrivateKey (*rsa.PrivateKey): A pointer to the generated RSA private key.
//   - err (error): An error with stack trace and metadata if key generation, SKI generation, serial number generation,
//     certificate creation, or parsing fails; otherwise, nil.
func (CA *CertificateAuthority) GenerateTLSCertificate(hosts []string, TLSCertificatePrivateKeyOptionFuncs ...TLSCertificatePrivateKeyOptionFunc) (TLSCertificate *x509.Certificate, TLSPrivateKey *rsa.PrivateKey, err error) {
	options := &_TLSCertificatePrivateKeyOptions{
		CommonName: "Acme CA",
		Organization: []string{
			"Acme Co",
		},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	for _, f := range TLSCertificatePrivateKeyOptionFuncs {
		f(options)
	}

	TLSPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate RSA private key")

		return
	}

	TLSPublicKey := TLSPrivateKey.Public()

	var TLSPrivateKeySKI []byte

	TLSPrivateKeySKI, err = generateSubjectKeyID(TLSPublicKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate subject key ID")

		return
	}

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate serial")

		return
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: options.Organization,
		},
		SubjectKeyId:          TLSPrivateKeySKI,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             options.ValidFrom.Add(-5 * time.Minute),
		NotAfter:              options.ValidFrom.Add(options.ValidFor),
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

	var TLSCertificateInBytes []byte

	TLSCertificateInBytes, err = x509.CreateCertificate(rand.Reader, template, CA._CACertificate, TLSPublicKey, CA._CAPrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to create certificate")

		return
	}

	TLSCertificate, err = x509.ParseCertificate(TLSCertificateInBytes)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to parse certificate")

		return
	}

	return
}

// NewTLSConfig creates a TLS configuration for use in a TLS server.
//
// The configuration includes a dynamic certificate generation function based on Server Name Indication
// (SNI) and sets a minimum TLS version of TLS 1.2. It also specifies supported protocols for
// Application-Layer Protocol Negotiation (ALPN), including HTTP/1.0, HTTP/1.1, and HTTP/2.0.
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
// The returned function is used as the GetCertificate callback in a tls.Config. It generates a new
// TLS certificate for the provided server name (from SNI) with a short validity period (24 hours).
// If the server name is missing, an error is returned. Errors are wrapped with context and metadata
// using hq-go-errors for better traceability.
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

		var TLSCertificate *x509.Certificate

		var TLSPrivateKey *rsa.PrivateKey

		TLSCertificate, TLSPrivateKey, err = CA.GenerateTLSCertificate([]string{host}, TLSCertificatePrivateKeyWithValidFor(24*time.Hour))
		if err != nil {
			err = hqgoerrors.Wrap(err, "failed to generate certificate")

			return
		}

		certificate = &tls.Certificate{
			Certificate: [][]byte{TLSCertificate.Raw, CA._CACertificate.Raw},
			PrivateKey:  TLSPrivateKey,
			Leaf:        TLSCertificate,
		}

		return
	}
}

// _TLSCertificatePrivateKeyOptions defines configuration options for generating a TLS certificate and private key pair.
// This struct is used internally to configure the properties of a TLS certificate signed by the CA.
//
// Fields:
//   - CommonName (string): Common Name (CN) for the certificate's subject, typically the CA's name (e.g., "Acme CA").
//   - Organization ([]string): Organization names included in the certificate's subject (e.g., ["Acme Co"]).
//   - ValidFrom (time.Time): The start time from which the certificate is valid. Defaults to the current time if not set.
//   - ValidFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365 days)
type _TLSCertificatePrivateKeyOptions struct {
	CommonName   string
	Organization []string
	ValidFrom    time.Time
	ValidFor     time.Duration
}

// TLSCertificatePrivateKeyOptionFunc is a function type for configuring _TLSCertificatePrivateKeyOptions
// using the functional options pattern. It allows flexible configuration of TLS certificate options.
//
// Parameters:
//   - options (*_TLSCertificatePrivateKeyOptions): A pointer to _TLSCertificatePrivateKeyOptions to be modified.
type TLSCertificatePrivateKeyOptionFunc func(options *_TLSCertificatePrivateKeyOptions)

// TLSCertificatePrivateKeyWithCommonName sets the Common Name (CN) for the TLS certificate's subject.
//
// Parameters:
//   - commonName (string): The Common Name to set in the certificate's subject (e.g., "Acme CA").
//
// Returns:
//   - (TLSCertificatePrivateKeyOptionFunc): A TLSCertificatePrivateKeyOptionFunc that updates the CommonName field of the options.
func TLSCertificatePrivateKeyWithCommonName(commonName string) TLSCertificatePrivateKeyOptionFunc {
	return func(options *_TLSCertificatePrivateKeyOptions) {
		options.CommonName = commonName
	}
}

// TLSCertificatePrivateKeyWithOrganization sets the Organization field for the TLS certificate's subject.
//
// Parameters:
//   - organization ([]string): A slice of organization names to set in the certificate's subject (e.g., ["Acme Co"]).
//
// Returns:
//   - (TLSCertificatePrivateKeyOptionFunc): A TLSCertificatePrivateKeyOptionFunc that updates the Organization field of the options.
func TLSCertificatePrivateKeyWithOrganization(organization []string) TLSCertificatePrivateKeyOptionFunc {
	return func(options *_TLSCertificatePrivateKeyOptions) {
		options.Organization = organization
	}
}

// TLSCertificatePrivateKeyWithValidFrom sets the start time for the TLS certificate's validity period.
//
// Parameters:
//   - validFrom (time.Time): The time from which the certificate is valid (e.g., time.Now()).
//
// Returns:
//   - (TLSCertificatePrivateKeyOptionFunc): A TLSCertificatePrivateKeyOptionFunc that updates the ValidFrom field of the options.
func TLSCertificatePrivateKeyWithValidFrom(validFrom time.Time) TLSCertificatePrivateKeyOptionFunc {
	return func(options *_TLSCertificatePrivateKeyOptions) {
		options.ValidFrom = validFrom
	}
}

// TLSCertificatePrivateKeyWithValidFor sets the duration for the TLS certificate's validity period.
//
// Parameters:
//   - validFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365*24*time.Hour).
//
// Returns:
//   - (TLSCertificatePrivateKeyOptionFunc): A TLSCertificatePrivateKeyOptionFunc that updates the ValidFor field of the options.
func TLSCertificatePrivateKeyWithValidFor(validFor time.Duration) TLSCertificatePrivateKeyOptionFunc {
	return func(options *_TLSCertificatePrivateKeyOptions) {
		options.ValidFor = validFor
	}
}

// New initializes a new CertificateAuthority with the provided CA certificate and private key.
//
// It verifies that the certificate is configured as a CA and has the necessary key usage for certificate
// signing. Errors are wrapped with context and metadata using hq-go-errors for improved debugging.
//
// Parameters:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the RSA private key corresponding to the CA certificate.
//
// Returns:
//   - CA (*CertificateAuthority): A pointer to the initialized CertificateAuthority.
//   - err (error): An error with stack trace and metadata if the CA certificate is invalid or lacks certSign key
//     usage; otherwise, nil.
func New(CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey) (CA *CertificateAuthority, err error) {
	if !CACertificate.IsCA {
		err = hqgoerrors.New("certificate is not configured as CA")

		return
	}

	if (CACertificate.KeyUsage & x509.KeyUsageCertSign) == 0 {
		err = hqgoerrors.New("CA certificate missing certSign key usage")

		return
	}

	CA = &CertificateAuthority{
		_CACertificate: CACertificate,
		_CAPrivateKey:  CAPrivateKey,
	}

	return
}

// normalizeHost normalizes a hostname by removing the port number if present.
//
// It splits the hostname using net.SplitHostPort and returns the host component. If no port is present,
// the original hostname is returned unchanged.
//
// Parameters:
//   - unnormalized (string): The hostname to normalize (e.g., "example.com:443").
//
// Returns:
//   - normalized (string): The normalized hostname (e.g., "example.com").
func normalizeHost(unnormalized string) (normalized string) {
	normalized = unnormalized

	if host, _, err := net.SplitHostPort(unnormalized); err == nil {
		normalized = host

		return
	}

	return
}
