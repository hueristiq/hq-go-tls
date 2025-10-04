package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// _CACertificatePrivateKeyOptions defines configuration options for generating a CA certificate and private key pair.
// This struct is used internally to configure the properties of a self-signed CA certificate.
//
// Fields:
//   - CommonName (string): Common Name (CN) for the certificate's subject, typically the CA's name (e.g., "Acme CA").
//   - Organization ([]string): Organization names included in the certificate's subject (e.g., ["Acme Co"]).
//   - ValidFrom (time.Time): The start time from which the certificate is valid. Defaults to the current time if not set.
//   - ValidFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365 days)
type _CACertificatePrivateKeyOptions struct {
	CommonName   string
	Organization []string
	ValidFrom    time.Time
	ValidFor     time.Duration
}

// CACertificatePrivateKeyOptionFunc is a function type used to configure _CACertificatePrivateKeyOptions
// using the functional options pattern. It allows flexible and extensible configuration of CA certificate options.
//
// Parameters:
//   - opts (*_CACertificatePrivateKeyOptions): A pointer to _CACertificatePrivateKeyOptions to be modified.
type CACertificatePrivateKeyOptionFunc func(opts *_CACertificatePrivateKeyOptions)

// CACertificatePrivateKeyWithCommonName sets the Common Name (CN) for the CA certificate's subject.
//
// Parameters:
//   - commonName (string): The Common Name to set in the certificate's subject (e.g., "Acme CA").
//
// Returns:
//   - (CACertificatePrivateKeyOptionFunc): A CACertificatePrivateKeyOptionFunc that updates the CommonName field of the options.
func CACertificatePrivateKeyWithCommonName(commonName string) CACertificatePrivateKeyOptionFunc {
	return func(opts *_CACertificatePrivateKeyOptions) {
		opts.CommonName = commonName
	}
}

// CACertificatePrivateKeyWithOrganization sets the Organization field for the CA certificate's subject.
//
// Parameters:
//   - organization ([]string): A slice of organization names to set in the certificate's subject (e.g., ["Acme Co"]).
//
// Returns:
//   - (CACertificatePrivateKeyOptionFunc): A CACertificatePrivateKeyOptionFunc that updates the Organization field of the options.
func CACertificatePrivateKeyWithOrganization(organization []string) CACertificatePrivateKeyOptionFunc {
	return func(opts *_CACertificatePrivateKeyOptions) {
		opts.Organization = organization
	}
}

// CACertificatePrivateKeyWithValidFrom sets the start time for the CA certificate's validity period.
//
// Parameters:
//   - validFrom (time.Time): The time from which the certificate is valid (e.g., time.Now()).
//
// Returns:
//   - (CACertificatePrivateKeyOptionFunc): A CACertificatePrivateKeyOptionFunc that updates the ValidFrom field of the options.
func CACertificatePrivateKeyWithValidFrom(validFrom time.Time) CACertificatePrivateKeyOptionFunc {
	return func(opts *_CACertificatePrivateKeyOptions) {
		opts.ValidFrom = validFrom
	}
}

// CACertificatePrivateKeyWithValidFor sets the duration for the CA certificate's validity period.
//
// Parameters:
//   - validFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365*24*time.Hour).
//
// Returns:
//   - (CACertificatePrivateKeyOptionFunc): A CACertificatePrivateKeyOptionFunc that updates the ValidFor field of the options.
func CACertificatePrivateKeyWithValidFor(validFor time.Duration) CACertificatePrivateKeyOptionFunc {
	return func(opts *_CACertificatePrivateKeyOptions) {
		opts.ValidFor = validFor
	}
}

// GenerateCACertificatePrivateKey generates a new X.509 CA certificate and its corresponding RSA private key.
//
// This function creates a 2048-bit RSA private key and a self-signed CA certificate based on the provided
// configuration options, using the functional options pattern. The certificate includes a random serial number,
// a subject key identifier (SKI), and is configured for key encipherment, digital signatures, and certificate signing,
// as per X.509 and RFC 5280 standards. The validity period starts at ValidFrom (defaulting to the current time) and
// extends for ValidFor (defaulting to 365 days). Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - ofs (...CACertificatePrivateKeyOptionFunc): A variadic list of CACertificatePrivateKeyOptionFunc functions to configure
//     the certificate's properties (e.g., CommonName, Organization, ValidFrom, ValidFor).
//
// Returns:
//   - CACertificate (*x509.Certificate): A pointer to the generated X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the generated RSA private key.
//   - err (error): An error with stack trace and metadata if key generation, SKI generation, serial number generation,
//     certificate creation, or parsing fails; otherwise, nil.
func GenerateCACertificatePrivateKey(ofs ...CACertificatePrivateKeyOptionFunc) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	opts := &_CACertificatePrivateKeyOptions{
		CommonName: "Acme CA",
		Organization: []string{
			"Acme Co",
		},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	for _, f := range ofs {
		f(opts)
	}

	CAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate RSA private key: %w", err)

		return
	}

	CAPublicKey := CAPrivateKey.Public()

	var CAPrivateKeySKI []byte

	CAPrivateKeySKI, err = generateSubjectKeyID(CAPublicKey)
	if err != nil {
		err = fmt.Errorf("failed to generate subject key ID: %w", err)

		return
	}

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = fmt.Errorf("failed to generate serial number: %w", err)

		return
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		SubjectKeyId:          CAPrivateKeySKI,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             opts.ValidFrom.Add(-5 * time.Minute),
		NotAfter:              opts.ValidFrom.Add(opts.ValidFor),
		DNSNames:              []string{opts.CommonName},
		IsCA:                  true,
	}

	var CACertificateInBytes []byte

	CACertificateInBytes, err = x509.CreateCertificate(rand.Reader, template, template, CAPublicKey, CAPrivateKey)
	if err != nil {
		err = fmt.Errorf("failed to create CA certificate: %w", err)

		return
	}

	CACertificate, err = x509.ParseCertificate(CACertificateInBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse CA certificate: %w", err)

		return
	}

	return
}

// LoadCACertificatePrivateKey loads a CA certificate and private key from the specified PEM-encoded files.
//
// The certificate and private key are loaded using the crypto/tls package. The certificate is parsed to ensure
// it is a valid X.509 certificate, and the private key is verified to be an RSA key. Errors are wrapped with context,
// error types, and metadata using hq-go-errors for better debugging and traceability.
//
// Parameters:
//   - CACertificateFilePath (string): The file path to the PEM-encoded CA certificate.
//   - CAPrivateKeyFilePath (string): The file path to the PEM-encoded private key.
//
// Returns:
//   - CACertificate ( *x509.Certificat): A pointer to the loaded X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the loaded RSA private key.
//   - err (error): An error with stack trace and metadata if loading, parsing, or type assertion fails; otherwise, nil.
func LoadCACertificatePrivateKey(CACertificateFilePath, CAPrivateKeyFilePath string) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	tlsCA, err := tls.LoadX509KeyPair(CACertificateFilePath, CAPrivateKeyFilePath)
	if err != nil {
		err = fmt.Errorf("failed to load CA certificate and private key: %w", err)

		return
	}

	CACertificate, err = x509.ParseCertificate(tlsCA.Certificate[0])
	if err != nil {
		err = fmt.Errorf("failed to parse CA certificate: %w", err)

		return
	}

	CAPrivateKey, ok := tlsCA.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("CA private key is not RSA: %w", err)

		return
	}

	return
}
