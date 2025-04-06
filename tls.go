package tls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertificateAuthority represents a custom Certificate Authority.
// It holds all necessary keys and identifiers to issue, sign, and manage TLS certificates dynamically.
// The fields are defined as follows:
type CertificateAuthority struct {
	_CACertificate            *x509.Certificate
	_CACertificatePrivateKey  *rsa.PrivateKey
	_TLSCertificatePrivateKey *rsa.PrivateKey
	_SubjectKeyID             []byte
}

// GetCACertificate returns the CA's x509.Certificate.
//
// Returns:
//   - CACertificate (*x509.Certificate): The certificate representing the Certificate Authority.
func (ca *CertificateAuthority) GetCACertificate() (CACertificate *x509.Certificate) {
	return ca._CACertificate
}

// NewTLSConfig creates a new tls.Config that utilizes the CA's dynamic TLS certificate generation.
// The configuration enforces a minimum TLS version of TLS 1.2 and supports common HTTP protocols.
//
// Returns:
//   - cfg (*tls.Config): A TLS configuration set up to call back to the CA for certificate generation.
func (ca *CertificateAuthority) NewTLSConfig() (cfg *tls.Config) {
	cfg = &tls.Config{
		GetCertificate: ca.getTLSCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.0", "http/1.1", "http/2.0"},
	}

	return
}

// getTLSCertificateFunc returns a function that implements tls.Config.GetCertificate.
// The returned function inspects the ClientHelloInfo for a valid SNI value and then generates a certificate for it.
//
// Returns:
//   - (func(*tls.ClientHelloInfo) (*tls.Certificate, error)): Callback function for TLS certificate selection.
func (ca *CertificateAuthority) getTLSCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
		// Verify that the client provided a Server Name Indication (SNI)
		if clientHello.ServerName == "" {
			err = fmt.Errorf("%w", ErrMissingSNI)

			return
		}

		// Generate a new TLS certificate based on the client's SNI.
		return ca.generateTLSCertificate(clientHello.ServerName)
	}
}

// generateTLSCertificate creates and signs a TLS certificate for the provided hostname.
// The certificate is signed using the CA's private key and is valid for 24 hours.
//
// Parameters:
//   - hostname (string): The hostname or IP address for which the certificate should be issued.
//
// Returns:
//   - certificate (*tls.Certificate): The generated TLS certificate along with its certificate chain.
//   - err (error): An error if there is a failure in generating or signing the certificate.
func (ca *CertificateAuthority) generateTLSCertificate(hostname string) (certificate *tls.Certificate, err error) {
	// Generate a random serial number for the new certificate.
	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = fmt.Errorf("failed to generate serial number: %w", err)

		return
	}

	// If the hostname contains a port, extract only the hostname.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	// Define the certificate template with required fields.
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

	// Set appropriate subject alternative names depending on whether the hostname is an IP or DNS name.
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	// Create the certificate by signing it with the CA's private key.
	var certificateInBytes []byte

	certificateInBytes, err = x509.CreateCertificate(rand.Reader, template, ca._CACertificate, ca._TLSCertificatePrivateKey.Public(), ca._CACertificatePrivateKey)
	if err != nil {
		err = fmt.Errorf("failed to create certificate: %w", err)

		return
	}

	// Parse the generated certificate so it can be attached as the Leaf certificate
	var leaf *x509.Certificate

	leaf, err = x509.ParseCertificate(certificateInBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse certificate: %w", err)

		return
	}

	// Assemble the TLS certificate structure, including the certificate chain.
	certificate = &tls.Certificate{
		Certificate: [][]byte{certificateInBytes, ca._CACertificate.Raw},
		PrivateKey:  ca._TLSCertificatePrivateKey,
		Leaf:        leaf,
	}

	return
}

var (
	ErrMissingSNI  = errors.New("missing server name (SNI)")
	ErrKeyIsNotRSA = errors.New("private key is not RSA")
)

// New creates and returns a new instance of CertificateAuthority.
// It requires a CA certificate and its corresponding private key to sign generated certificates.
// Additionally, it generates a separate TLS private key and computes its subject key identifier.
//
// Parameters:
//   - CACertificate (*x509.Certificate): The certificate for the Certificate Authority.
//   - CACertificatePrivateKey (*rsa.PrivateKey): The RSA private key corresponding to the CA certificate.
//
// Returns:
//   - ca (*CertificateAuthority): A pointer to the newly created CertificateAuthority instance.
//   - err (error): An error if TLS key generation or subject key identifier computation fails.
func New(CACertificate *x509.Certificate, CACertificatePrivateKey *rsa.PrivateKey) (ca *CertificateAuthority, err error) {
	// Generate a new RSA private key to be used for signing TLS certificates.
	var TLSPrivateKey *rsa.PrivateKey

	TLSPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate TLS private key: %w", err)

		return
	}

	// Compute the subject key identifier from the TLS private key's public component.
	publicKey := TLSPrivateKey.Public()

	var subjectKeyID []byte

	subjectKeyID, err = generateSubjectKeyID(publicKey)
	if err != nil {
		err = fmt.Errorf("failed to generate subject key ID: %w", err)

		return
	}

	// Construct the CertificateAuthority struct with all required fields.
	ca = &CertificateAuthority{
		_CACertificate:            CACertificate,
		_CACertificatePrivateKey:  CACertificatePrivateKey,
		_TLSCertificatePrivateKey: TLSPrivateKey,
		_SubjectKeyID:             subjectKeyID,
	}

	return
}

// LoadOrGenerateAuthority attempts to load an existing CA certificate and its private key from disk.
// If the files do not exist, it generates a new CA certificate and key pair and writes them to disk.
//
// Parameters:
//   - CACertificateFile (string): Path to the file containing the PEM-encoded CA certificate.
//   - CACertificatePrivateKeyFile (string): Path to the file containing the PEM-encoded CA private key.
//
// Returns:
//   - CACertificate (*x509.Certificate): The loaded or newly generated CA certificate.
//   - CACertificatePrivateKey (*rsa.PrivateKey): The corresponding CA RSA private key.
//   - err (error): An error if loading or generation fails.
func LoadOrGenerateAuthority(CACertificateFile, CACertificatePrivateKeyFile string) (CACertificate *x509.Certificate, CACertificatePrivateKey *rsa.PrivateKey, err error) {
	// Attempt to load an existing CA certificate and key from the specified files.
	CACertificate, CACertificatePrivateKey, err = loadAuthority(CACertificateFile, CACertificatePrivateKeyFile)
	if err == nil {
		return
	}

	// If the error is not due to files missing, return the error.
	if !os.IsNotExist(err) {
		err = fmt.Errorf("could not load CA key pair: %w", err)

		return
	}

	name := "Hueristiq CA"
	organisation := "Hueristiq"
	varidity := 365 * 24 * time.Hour

	// Generate a new CA certificate and private key.
	CACertificate, CACertificatePrivateKey, err = generateAuthority(name, organisation, varidity)
	if err != nil {
		return
	}

	// Write the generated CA certificate and private key to disk.
	if err = writeCertificateAuthorityKeyPair(CACertificate, CACertificateFile, CACertificatePrivateKey, CACertificatePrivateKeyFile); err != nil {
		return
	}

	return
}

// loadAuthority loads a CA certificate and its private key from the specified files.
// It expects the certificate and key to be in PEM format and the key to be RSA.
//
// Parameters:
//   - CACertificateFile (string): Path to the PEM-encoded CA certificate.
//   - CACertificatePrivateKeyFile (string): Path to the PEM-encoded CA private key.
//
// Returns:
//   - CACertificate (*x509.Certificate): The loaded CA certificate.
//   - CACertificatePrivateKey (*rsa.PrivateKey): The loaded RSA private key.
//   - err (error): An error if the file cannot be read or parsed.
func loadAuthority(CACertificateFile, CACertificatePrivateKeyFile string) (CACertificate *x509.Certificate, CACertificatePrivateKey *rsa.PrivateKey, err error) {
	// Load the certificate and private key using the TLS package helper.
	tlsCA, err := tls.LoadX509KeyPair(CACertificateFile, CACertificatePrivateKeyFile)
	if err != nil {
		return
	}

	// Parse the first certificate in the chain.
	CACertificate, err = x509.ParseCertificate(tlsCA.Certificate[0])
	if err != nil {
		err = fmt.Errorf("could not parse CA: %w", err)

		return
	}

	// Ensure the private key is of RSA type.
	CACertificatePrivateKey, ok := tlsCA.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("%w", ErrKeyIsNotRSA)

		return
	}

	return
}

// generateAuthority creates a new self-signed CA certificate along with its RSA private key.
// It sets up the certificate with a given name, organization, and validity period.
//
// Parameters:
//   - name (string): The common name (CN) for the CA certificate.
//   - organization (string): The organization name to include in the certificate.
//   - validity (time.Duration): The duration for which the CA certificate will be valid.
//
// Returns:
//   - CACertificate (*x509.Certificate): The generated self-signed CA certificate.
//   - CACertificatePrivateKey (*rsa.PrivateKey): The RSA private key for the CA certificate.
//   - err (error): An error if key generation or certificate creation fails.
func generateAuthority(name, organization string, validity time.Duration) (CACertificate *x509.Certificate, CACertificatePrivateKey *rsa.PrivateKey, err error) {
	// Generate a new RSA private key for the CA.
	CACertificatePrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	// Obtain the public key from the generated private key.
	CAPublicKey := CACertificatePrivateKey.Public()

	// Compute a subject key identifier based on the public key.
	var subjectKeyID []byte

	subjectKeyID, err = generateSubjectKeyID(CAPublicKey)
	if err != nil {
		return
	}

	// Generate a random serial number for the certificate.
	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		return
	}

	// Set up the CA certificate template.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          subjectKeyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	// Create the self-signed CA certificate.
	var CACertificateInBytes []byte

	CACertificateInBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, CAPublicKey, CACertificatePrivateKey)
	if err != nil {
		return
	}

	// Parse the generated certificate into an x509.Certificate object.
	CACertificate, err = x509.ParseCertificate(CACertificateInBytes)
	if err != nil {
		return
	}

	return
}

// generateSubjectKeyID computes the subject key identifier for the given public key.
// The identifier is generated by marshaling the public key into PKIX format and then taking its SHA-256 hash.
//
// Parameters:
//   - publicKey (crypto.PublicKey): The public key for which the identifier is computed.
//
// Returns:
//   - keyID ([]byte): The computed subject key identifier.
//   - err (error): An error if marshaling the public key fails.
func generateSubjectKeyID(publicKey crypto.PublicKey) (keyID []byte, err error) {
	// Marshal the public key into PKIX (X.509) format.
	pkixPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}

	// Compute the SHA-256 hash of the marshaled public key.
	hash := sha256.New()

	hash.Write(pkixPub)

	keyID = hash.Sum(nil)

	return
}

// generateSerialNumber produces a random serial number for certificate issuance.
//
// Returns:
//   - serialNumber (*big.Int): A random serial number.
//   - err (error): An error if random number generation fails.
func generateSerialNumber() (serialNumber *big.Int, err error) {
	serialNumber, err = rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		err = fmt.Errorf("error generating SNI: %w", err)

		return
	}

	return
}

// writeCertificateAuthorityKeyPair writes the CA certificate and private key to disk in PEM format.
// It ensures that the destination directories exist and that the files are written with secure permissions.
//
// Parameters:
//   - CACertificate (*x509.Certificate): The CA certificate to be written.
//   - CACertificateFile (string): The file path for saving the CA certificate.
//   - CACertificatePrivateKey (*rsa.PrivateKey): The CA's private key.
//   - CACertificatePrivateKeyFile (string): The file path for saving the CA private key.
//
// Returns:
//   - err (error): An error if directory creation, PEM encoding, or file writing fails.
func writeCertificateAuthorityKeyPair(CACertificate *x509.Certificate, CACertificateFile string, CACertificatePrivateKey *rsa.PrivateKey, CACertificatePrivateKeyFile string) (err error) {
	// Ensure the directory for the CA certificate exists.
	caCertFileDirectory := filepath.Dir(CACertificateFile)

	if err = mkdir(caCertFileDirectory); err != nil {
		err = fmt.Errorf("could not create directory for CA cert: %w", err)

		return
	}

	// Convert the CA certificate to PEM format.
	var CACertificateContent *bytes.Buffer

	CACertificateContent, err = CertificateAuthorityCertificateToPEM(CACertificate)
	if err != nil {
		return
	}

	// Write the PEM-encoded CA certificate to the specified file.
	if err = writeToFile(CACertificateContent, CACertificateFile); err != nil {
		return
	}

	// Convert the CA private key to PEM format.
	var CACertificatePrivateKeyContent *bytes.Buffer

	CACertificatePrivateKeyContent, err = CertificateAuthorityPrivateKeyToPEM(CACertificatePrivateKey)
	if err != nil {
		return
	}

	// Write the PEM-encoded CA private key to the specified file.
	if err = writeToFile(CACertificatePrivateKeyContent, CACertificatePrivateKeyFile); err != nil {
		return
	}

	return
}

// CertificateAuthorityCertificateToPEM converts a CA certificate into PEM format.
//
// Parameters:
//   - CACertificate (*x509.Certificate): The CA certificate to encode.
//
// Returns:
//   - raw (*bytes.Buffer): A buffer containing the PEM-encoded certificate.
//   - err (error): An error if PEM encoding fails.
func CertificateAuthorityCertificateToPEM(CACertificate *x509.Certificate) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	if err = pem.Encode(raw, &pem.Block{Type: "CERTIFICATE", Bytes: CACertificate.Raw}); err != nil {
		return
	}

	return
}

// CertificateAuthorityPrivateKeyToPEM converts a CA RSA private key into PEM format.
//
// Parameters:
//   - CACertificatePrivateKey (*rsa.PrivateKey): The CA private key to encode.
//
// Returns:
//   - raw (*bytes.Buffer): A buffer containing the PEM-encoded private key.
//   - err (error): An error if marshaling or PEM encoding fails.
func CertificateAuthorityPrivateKeyToPEM(CACertificatePrivateKey *rsa.PrivateKey) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	// Marshal the RSA private key into PKCS#8 format.
	var CACertificatePrivateKeyBytes []byte

	CACertificatePrivateKeyBytes, err = x509.MarshalPKCS8PrivateKey(CACertificatePrivateKey)
	if err != nil {
		return
	}

	// PEM-encode the private key.
	if err = pem.Encode(raw, &pem.Block{Type: "PRIVATE KEY", Bytes: CACertificatePrivateKeyBytes}); err != nil {
		return
	}

	return
}

// mkdir creates the specified directory path if it does not already exist.
//
// Parameters:
//   - path (string): The directory path to create.
//
// Returns:
//   - err (error): An error if directory creation fails.
func mkdir(path string) (err error) {
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(path, 0o755); err != nil {
			err = fmt.Errorf("error creating directory %q: %w", path, err)

			return
		}
	}

	return
}

// writeToFile writes the contents of a bytes.Buffer to a file with secure permissions (mode 0600).
//
// Parameters:
//   - content (*bytes.Buffer): The content to write to the file.
//   - file (string): The file path where the content should be saved.
//
// Returns:
//   - err (error): An error if writing to the file fails.
func writeToFile(content *bytes.Buffer, file string) (err error) {
	if err = os.WriteFile(file, content.Bytes(), 0o600); err != nil {
		err = fmt.Errorf("error writing file %q: %w", file, err)
	}

	return
}
