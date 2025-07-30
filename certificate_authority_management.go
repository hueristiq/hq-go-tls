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

	hqgoerrors "github.com/hueristiq/hq-go-errors"
)

// CACertificatePrivateKeyOptions defines configuration options for generating a CA certificate
// and private key pair.
//
// Fields:
//   - CommonName (string): The Common Name (CN) for the certificate's subject, typically the CA's name.
//   - Organization ([]string): A slice of organization names included in the certificate's subject.
//   - Validity (time.Duration): The duration for which the certificate is valid, starting from the current time.
type CACertificatePrivateKeyOptions struct {
	CommonName   string
	Organization []string
	Validity     time.Duration
}

// GenerateCACertificatePrivateKey generates a new X.509 CA certificate and its corresponding RSA private key.
//
// This function creates a 2048-bit RSA private key and a self-signed CA certificate based on the provided
// options. The certificate includes a random serial number, a subject key identifier (SKI), and is configured
// for key encipherment, digital signatures, and certificate signing. The certificate is valid from the current
// time until the specified validity duration. Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - options (*CACertificatePrivateKeyOptions): A pointer to CACertificatePrivateKeyOptions specifying the certificate's subject and validity.
//
// Returns:
//   - CACertificate (*x509.Certificate): A pointer to the generated X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the generated RSA private key.
//   - err (error): An error with stack trace and metadata if key generation, SKI generation, serial number generation,
//     certificate creation, or parsing fails; otherwise, nil.
func GenerateCACertificatePrivateKey(options *CACertificatePrivateKeyOptions) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	CAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate RSA private key")

		return
	}

	CAPublicKey := CAPrivateKey.Public()

	var SKI []byte

	SKI, err = generateSubjectKeyID(CAPublicKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate subject key ID")

		return
	}

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate serial number")

		return
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   options.CommonName,
			Organization: options.Organization,
		},
		SubjectKeyId:          SKI,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             now,
		NotAfter:              now.Add(options.Validity),
		DNSNames:              []string{options.CommonName},
		IsCA:                  true,
	}

	var CACertificateInBytes []byte

	CACertificateInBytes, err = x509.CreateCertificate(rand.Reader, template, template, CAPublicKey, CAPrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to create CA certificate")

		return
	}

	CACertificate, err = x509.ParseCertificate(CACertificateInBytes)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to parse CA certificate")

		return
	}

	return
}

// LoadCACertificatePrivateKey loads a CA certificate and private key from the specified files.
//
// The certificate and private key are loaded from PEM-encoded files using the crypto/tls package.
// The certificate is parsed to ensure it is a valid X.509 certificate, and the private key is
// verified to be an RSA key. Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - CACertificateFile (string): The file path to the PEM-encoded CA certificate.
//   - CAPrivateKeyFile (string): The file path to the PEM-encoded private key.
//
// Returns:
//   - CACertificate (*x509.Certificate): A pointer to the loaded X.509 CA certificate.
//   - CAPrivateKey (*rsa.PrivateKey): A pointer to the loaded RSA private key.
//   - err (error): An error with stack trace and metadata if loading, parsing, or type assertion fails;
//     otherwise, nil.
func LoadCACertificatePrivateKey(CACertificateFile, CAPrivateKeyFile string) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	tlsCA, err := tls.LoadX509KeyPair(CACertificateFile, CAPrivateKeyFile)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to load CA certificate and private key", hqgoerrors.WithField("certificate_file", CACertificateFile), hqgoerrors.WithField("private_key_file", CAPrivateKeyFile))

		return
	}

	CACertificate, err = x509.ParseCertificate(tlsCA.Certificate[0])
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to parse CA certificate", hqgoerrors.WithField("certificate_file", CACertificateFile))

		return
	}

	CAPrivateKey, ok := tlsCA.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		err = hqgoerrors.New("private key is not RSA", hqgoerrors.WithField("private_key_file", CAPrivateKeyFile), hqgoerrors.WithField("actual_type", fmt.Sprintf("%T", tlsCA.PrivateKey)))

		return
	}

	return
}
