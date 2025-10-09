package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCertificatePrivateKeyFromFiles loads a certificate and private key from the specified PEM-encoded files.
//
// The certificate and private key are loaded using the crypto/tls package. The certificate is parsed to ensure
// it is a valid X.509 certificate, and the private key is verified to implement the crypto.Signer interface
// and to be one of the supported types (RSA, ECDSA, or Ed25519).
//
// Parameters:
//   - certificateFilePath (string): The file path to the PEM-encoded certificate.
//   - certificatePrivateKeyFilePath (string): The file path to the PEM-encoded private key.
//
// Returns:
//   - certificate (*x509.Certificate): A pointer to the loaded X.509 certificate.
//   - certificatePrivateKey (crypto.Signer): The loaded private key, implementing the crypto.Signer interface.
//   - err (error): An error with stack trace and metadata if loading, parsing, or type assertion fails; otherwise, nil.
func LoadCertificatePrivateKeyFromFiles(certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, certificatePrivateKey crypto.Signer, err error) {
	tlsCA, err := tls.LoadX509KeyPair(certificateFilePath, certificatePrivateKeyFilePath)
	if err != nil {
		err = fmt.Errorf("failed to load certificate and private key: %w", err)

		return
	}

	certificate, err = x509.ParseCertificate(tlsCA.Certificate[0])
	if err != nil {
		err = fmt.Errorf("failed to parse certificate: %w", err)

		return
	}

	switch certificatePrivateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		err = fmt.Errorf("unsupported private key type: %T", certificatePrivateKey)

		return
	}

	return
}

// SaveCertificatePrivateKeyToFiles saves a certificate and its private key to the specified files in PEM format.
//
// The certificate and private key are converted to PEM format and written to the provided file paths.
// The directory for the certificate file is created with permissions 0755 if it does not exist. Files are
// written with restrictive permissions (0600) to ensure security for sensitive data. The private key must
// implement the crypto.Signer interface and be one of the supported types (RSA, ECDSA, or Ed25519).
//
// Parameters:
//   - certificate (*x509.Certificate): A pointer to the X.509 certificate to save.
//   - certificateFilePath (string): The file path where the certificate will be saved in PEM format.
//   - certificatePrivateKey (crypto.Signer): The private key to save, implementing the crypto.Signer interface.
//   - certificatePrivateKeyFilePath (string): The file path where the private key will be saved in PEM format.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation, PEM conversion, or file writing
//     fails; otherwise, nil.
func SaveCertificatePrivateKeyToFiles(certificate *x509.Certificate, certificateFilePath string, certificatePrivateKey crypto.Signer, certificatePrivateKeyFilePath string) (err error) {
	certificateFilePathDirectory := filepath.Dir(certificateFilePath)

	if err = mkdir(certificateFilePathDirectory); err != nil {
		err = fmt.Errorf("failed to create directory for certificate: %w", err)

		return
	}

	var certificateBytes []byte

	certificateBytes, err = CertificateToPEM(certificate)
	if err != nil {
		err = fmt.Errorf("failed to convert certificate to PEM: %w", err)

		return
	}

	if err = writeToFile(certificateBytes, certificateFilePath); err != nil {
		err = fmt.Errorf("failed to write certificate to file: %w", err)

		return
	}

	var keyBytes []byte

	keyBytes, err = PrivateKeyToPEM(certificatePrivateKey)
	if err != nil {
		err = fmt.Errorf("failed to convert private key to PEM: %w", err)

		return
	}

	if err = writeToFile(keyBytes, certificatePrivateKeyFilePath); err != nil {
		err = fmt.Errorf("failed to write private key to file: %w", err)

		return
	}

	return
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755 (rwxr-xr-x), suitable for directories containing
// certificate files. If the directory already exists, no action is taken.
//
// Parameters:
//   - path (string): The file system path for the directory to create.
//
// Returns:
//   - err (error): An error with stack trace and metadata if directory creation fails; otherwise, nil.
func mkdir(path string) (err error) {
	if _, err = os.Stat(path); os.IsNotExist(err) {
		if err = os.MkdirAll(path, 0o755); err != nil {
			err = fmt.Errorf("failed to create directory: %w", err)

			return
		}
	}

	return
}

// writeToFile writes the content of a byte slice to a file with restrictive permissions.
//
// The file is written with permissions 0600 (rw-------) to ensure security for sensitive data like
// certificates and private keys.
//
// Parameters:
//   - content ([]byte): A byte slice containing the data to write.
//   - path (string): The file path where the content will be written.
//
// Returns:
//   - err (error): An error with stack trace and metadata if file writing fails; otherwise, nil.
func writeToFile(content []byte, path string) (err error) {
	if err = os.WriteFile(path, content, 0o600); err != nil {
		err = fmt.Errorf("failed to write to file: %w", err)
	}

	return
}
