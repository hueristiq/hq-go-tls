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

func GenerateCACertificatePrivateKey(name, organization string, validity time.Duration) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	CAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	CAPublicKey := CAPrivateKey.Public()

	var subjectKeyID []byte

	subjectKeyID, err = generateSubjectKeyID(CAPublicKey)
	if err != nil {
		return
	}

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		return
	}

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

	var CACertificateInBytes []byte

	CACertificateInBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, CAPublicKey, CAPrivateKey)
	if err != nil {
		return
	}

	CACertificate, err = x509.ParseCertificate(CACertificateInBytes)
	if err != nil {
		return
	}

	return
}

func SaveCACertificatePrivateKey(CACertificate *x509.Certificate, CACertificateFile string, CACertificatePrivateKey *rsa.PrivateKey, CACertificatePrivateKeyFile string) (err error) {
	caCertFileDirectory := filepath.Dir(CACertificateFile)

	if err = mkdir(caCertFileDirectory); err != nil {
		err = fmt.Errorf("could not create directory for CA cert: %w", err)

		return
	}

	var CACertificateContent *bytes.Buffer

	CACertificateContent, err = _CACertificateToPEM(CACertificate)
	if err != nil {
		return
	}

	if err = writeToFile(CACertificateContent, CACertificateFile); err != nil {
		return
	}

	var CAPrivateKeyContent *bytes.Buffer

	CAPrivateKeyContent, err = _CAPrivateKeyToPEM(CACertificatePrivateKey)
	if err != nil {
		return
	}

	if err = writeToFile(CAPrivateKeyContent, CACertificatePrivateKeyFile); err != nil {
		return
	}

	return
}

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

func _CACertificateToPEM(CACertificate *x509.Certificate) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	if err = pem.Encode(raw, &pem.Block{Type: "CERTIFICATE", Bytes: CACertificate.Raw}); err != nil {
		return
	}

	return
}

func _CAPrivateKeyToPEM(CACertificatePrivateKey *rsa.PrivateKey) (raw *bytes.Buffer, err error) {
	raw = new(bytes.Buffer)

	var CACertificatePrivateKeyBytes []byte

	CACertificatePrivateKeyBytes, err = x509.MarshalPKCS8PrivateKey(CACertificatePrivateKey)
	if err != nil {
		return
	}

	if err = pem.Encode(raw, &pem.Block{Type: "PRIVATE KEY", Bytes: CACertificatePrivateKeyBytes}); err != nil {
		return
	}

	return
}

func writeToFile(content *bytes.Buffer, file string) (err error) {
	if err = os.WriteFile(file, content.Bytes(), 0o600); err != nil {
		err = fmt.Errorf("error writing file %q: %w", file, err)
	}

	return
}

func LoadCACertificatePrivateKey(CACertificateFile, CAPrivateKeyFile string) (CACertificate *x509.Certificate, CAPrivateKey *rsa.PrivateKey, err error) {
	tlsCA, err := tls.LoadX509KeyPair(CACertificateFile, CAPrivateKeyFile)
	if err != nil {
		return
	}

	CACertificate, err = x509.ParseCertificate(tlsCA.Certificate[0])
	if err != nil {
		err = hqgoerrors.Wrap(err, "could not parse CA")

		return
	}

	CAPrivateKey, ok := tlsCA.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		err = hqgoerrors.New("private key is not RSA")

		return
	}

	return
}
