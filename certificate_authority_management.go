package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

// SaveCACertificatePrivateKey saves a CA certificate and its private key to the specified files in PEM format.
//
// The certificate and private key are converted to PEM format and written to the provided file paths.
// The directory for the certificate file is created if it does not exist. Files are written with
// restrictive permissions (0600). Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 CA certificate to save.
//   - CACertificateFile (string): The file path where the certificate will be saved in PEM format.
//   - CACertificatePrivateKey (*rsa.PrivateKey): A pointer to the RSA private key to save.
//   - CACertificatePrivateKeyFile (string): The file path where the private key will be saved in PEM format.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation, PEM conversion, or file writing fails;
//     otherwise, nil.
func SaveCACertificatePrivateKey(CACertificate *x509.Certificate, CACertificateFile string, CACertificatePrivateKey *rsa.PrivateKey, CACertificatePrivateKeyFile string) (err error) {
	caCertFileDirectory := filepath.Dir(CACertificateFile)

	if err = mkdir(caCertFileDirectory); err != nil {
		err = hqgoerrors.Wrap(err, "failed to create directory for CA certificate", hqgoerrors.WithField("directory", caCertFileDirectory))

		return
	}

	var CACertificateContent *bytes.Buffer

	CACertificateContent, err = CACertificateToPEM(CACertificate)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to convert CA certificate to PEM")

		return
	}

	if err = writeToFile(CACertificateContent, CACertificateFile); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write CA certificate to file", hqgoerrors.WithField("file", CACertificateFile))

		return
	}

	var CAPrivateKeyContent *bytes.Buffer

	CAPrivateKeyContent, err = CAPrivateKeyToPEM(CACertificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to convert CA private key to PEM")

		return
	}

	if err = writeToFile(CAPrivateKeyContent, CACertificatePrivateKeyFile); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write CA private key to file", hqgoerrors.WithField("file", CACertificatePrivateKeyFile))

		return
	}

	return
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755. If the directory already exists, no action is taken.
// Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - directory (string): The file system path for the directory to create.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation fails; otherwise, nil.
func mkdir(directory string) (err error) {
	_, err = os.Stat(directory)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(directory, 0o755); err != nil {
			err = hqgoerrors.Wrap(err, "failed to create directory", hqgoerrors.WithField("directory", directory))

			return
		}
	}

	return
}

// CACertificateToPEM converts an X.509 certificate to PEM format.
//
// The certificate is encoded as a PEM block with type "CERTIFICATE". Errors are wrapped with
// context and metadata using hq-go-errors.
//
// Parameters:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 certificate to convert.
//
// Returns:
//   - raw (*bytes.Buffer): A bytes.Buffer containing the PEM-encoded certificate.
//   - err (error): An error with stack trace and metadata if PEM encoding fails; otherwise, nil.
func CACertificateToPEM(CACertificate *x509.Certificate) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	if err = pem.Encode(raw, &pem.Block{Type: "CERTIFICATE", Bytes: CACertificate.Raw}); err != nil {
		err = hqgoerrors.Wrap(err, "failed to encode CA certificate to PEM")

		return
	}

	return
}

// CAPrivateKeyToPEM converts an RSA private key to PEM format.
//
// The private key is marshaled to PKCS#8 format and encoded as a PEM block with type "PRIVATE KEY".
// Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - CACertificatePrivateKey (*rsa.PrivateKey): A pointer to the RSA private key to convert.
//
// Returns:
//   - raw (*bytes.Buffer): A bytes.Buffer containing the PEM-encoded private key.
//   - err (error): An error with stack trace and metadata if marshaling or PEM encoding fails; otherwise, nil.
func CAPrivateKeyToPEM(CACertificatePrivateKey *rsa.PrivateKey) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	var CACertificatePrivateKeyBytes []byte

	CACertificatePrivateKeyBytes, err = x509.MarshalPKCS8PrivateKey(CACertificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to marshal CA private key to PKCS#8")

		return
	}

	if err = pem.Encode(raw, &pem.Block{Type: "PRIVATE KEY", Bytes: CACertificatePrivateKeyBytes}); err != nil {
		err = hqgoerrors.Wrap(err, "failed to encode CA private key to PEM")

		return
	}

	return
}

// writeToFile writes the content of a bytes.Buffer to a file with restrictive permissions.
//
// The file is written with permissions 0600 to ensure security for sensitive data like certificates
// and private keys. Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - content (*bytes.Buffer): A bytes.Buffer containing the data to write.
//   - file (string): The file path where the content will be written.
//
// Returns:
//   - err (error): An error with stack trace and metadata if file writing fails; otherwise, nil.
func writeToFile(content *bytes.Buffer, file string) (err error) {
	if err = os.WriteFile(file, content.Bytes(), 0o600); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write to file", hqgoerrors.WithField("file", file))
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
