package tls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"

	hqgoerrors "github.com/hueristiq/hq-go-errors"
)

// generateSerialNumber creates a random serial number for use in X.509 certificates.
//
// Serial numbers are unique identifiers for certificates, as required by the X.509 standard (RFC 5280).
// This function generates a cryptographically secure random number with a maximum bit length of 128 bits,
// ensuring compliance with common certificate authority requirements. If the generated number is zero,
// it defaults to 1 to avoid invalid serial numbers, as zero is not a valid serial number per X.509.
//
// Returns:
//   - serialNumber (*big.Int): A pointer to a big.Int representing the generated serial number.
//   - err (error): An error with stack trace and metadata if random number generation fails; otherwise, nil.
func generateSerialNumber() (serialNumber *big.Int, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to generate random serial number")

		return
	}

	if serialNumber.Sign() == 0 {
		serialNumber = big.NewInt(1)
	}

	return
}

// generateSubjectKeyID computes a Subject Key Identifier (SKI) from a given public key.
//
// The Subject Key Identifier is a SHA-1 hash of the public key's PKIX-encoded form, as specified in
// RFC 5280, section 4.2.1.2. It is used to uniquely identify a public key in an X.509 certificate.
// The public key is marshaled to PKIX format before hashing. If marshaling fails or the key is empty,
// an error is returned with appropriate context.
//
// Parameters:
//   - publicKey (crypto.PublicKey): The cryptographic public key (e.g., *rsa.PublicKey) to generate the SKI for.
//
// Returns:
//   - SKI ([]byte): A byte slice containing the SHA-1 hash of the marshaled public key.
//   - err (error): An error with stack trace and metadata if public key marshaling fails or the key is empty;
//     otherwise, nil.
func generateSubjectKeyID(publicKey crypto.PublicKey) (SKI []byte, err error) {
	pkixPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to marshal public key to PKIX format")

		return
	}

	if len(pkixPub) == 0 {
		err = hqgoerrors.New("public key is enpty!")

		return
	}

	sum := sha1.Sum(pkixPub)

	SKI = sum[:]

	return
}

// SaveCertificatePrivateKey saves a certificate and its private key to the specified files in PEM format.
//
// The certificate and private key are converted to PEM format and written to the provided file paths.
// The directory for the certificate file is created with permissions 0755 if it does not exist. Files are
// written with restrictive permissions (0600) to ensure security for sensitive data. Errors are wrapped
// with context and metadata using hq-go-errors for improved debugging and traceability.
//
// Parameters:
//   - certificate (*x509.Certificate): A pointer to the X.509 certificate to save.
//   - certificateFilePath (string): The file path where the certificate will be saved in PEM format.
//   - certificatePrivateKey (*rsa.PrivateKey): A pointer to the RSA private key to save.
//   - certificatePrivKeyFilePath (string): The file path where the private key will be saved in PEM format.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation, PEM conversion, or file writing
//     fails; otherwise, nil.
func SaveCertificatePrivateKey(certificate *x509.Certificate, certificateFilePath string, certificatePrivateKey *rsa.PrivateKey, certificatePrivKeyFilePath string) (err error) {
	certificateFilePathDirectory := filepath.Dir(certificateFilePath)

	if err = mkdir(certificateFilePathDirectory); err != nil {
		err = hqgoerrors.Wrap(err, "failed to create directory for certificate", hqgoerrors.WithField("path", certificateFilePathDirectory))

		return
	}

	var certificateContent *bytes.Buffer

	certificateContent, err = CertificateToPEM(certificate)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to convert certificate to PEM")

		return
	}

	if err = writeToFile(certificateContent, certificateFilePath); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write certificate to file", hqgoerrors.WithField("path", certificateFilePath))

		return
	}

	var privKeyContent *bytes.Buffer

	privKeyContent, err = PrivateKeyToPEM(certificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to convert private key to PEM")

		return
	}

	if err = writeToFile(privKeyContent, certificatePrivKeyFilePath); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write private key to file", hqgoerrors.WithField("path", certificatePrivKeyFilePath))

		return
	}

	return
}

// CertificateToPEM converts an X.509 certificate to PEM format.
//
// The certificate is encoded as a PEM block with type "CERTIFICATE", as per RFC 7468. The resulting
// PEM data is written to a bytes.Buffer for further use (e.g., writing to a file or network). Errors
// are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - certificate (*x509.Certificate): A pointer to the X.509 certificate to convert.
//
// Returns:
//   - raw (*bytes.Buffer): A bytes.Buffer containing the PEM-encoded certificate.
//   - err (error): An error with stack trace and metadata if PEM encoding fails; otherwise, nil.
func CertificateToPEM(certificate *x509.Certificate) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	if err = pem.Encode(raw, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
		err = hqgoerrors.Wrap(err, "failed to encode certificate to PEM")

		return
	}

	return
}

// PrivateKeyToPEM converts an RSA private key to PEM format.
//
// The private key is marshaled to PKCS#8 format (per RFC 5208) and encoded as a PEM block with type
// "PRIVATE KEY", as per RFC 7468. The resulting PEM data is written to a bytes.Buffer. Errors are
// wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - certificatePrivateKey (*rsa.PrivateKey): A pointer to the RSA private key to convert.
//
// Returns:
//   - raw (*bytes.Buffer): A bytes.Buffer containing the PEM-encoded private key.
//   - err (error): An error with stack trace and metadata if marshaling or PEM encoding fails; otherwise, nil.
func PrivateKeyToPEM(certificatePrivateKey *rsa.PrivateKey) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	var certificatePrivateKeyBytes []byte

	certificatePrivateKeyBytes, err = x509.MarshalPKCS8PrivateKey(certificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "failed to marshal private key to PKCS#8")

		return
	}

	if err = pem.Encode(raw, &pem.Block{Type: "PRIVATE KEY", Bytes: certificatePrivateKeyBytes}); err != nil {
		err = hqgoerrors.Wrap(err, "failed to encode private key to PEM")

		return
	}

	return
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755 (rwxr-xr-x), suitable for directories containing
// certificate files. If the directory already exists, no action is taken. Errors are wrapped with
// context and metadata using hq-go-errors for better traceability.
//
// Parameters:
//   - path (string): The file system path for the directory to create.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation fails; otherwise, nil.
func mkdir(path string) (err error) {
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(path, 0o755); err != nil {
			err = hqgoerrors.Wrap(err, "failed to create directory", hqgoerrors.WithField("path", path))

			return
		}
	}

	return
}

// writeToFile writes the content of a bytes.Buffer to a file with restrictive permissions.
//
// The file is written with permissions 0600 (rw-------) to ensure security for sensitive data like
// certificates and private keys. Errors are wrapped with context and metadata using hq-go-errors.
//
// Parameters:
//   - content (*bytes.Buffer): A bytes.Buffer containing the data to write.
//   - path (string): The file path where the content will be written.
//
// Returns:
//   - err (error): An error with stack trace and metadata if file writing fails; otherwise, nil.
func writeToFile(content *bytes.Buffer, path string) (err error) {
	if err = os.WriteFile(path, content.Bytes(), 0o600); err != nil {
		err = hqgoerrors.Wrap(err, "failed to write to file", hqgoerrors.WithField("path", path))
	}

	return
}
