package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"net/mail"
	"net/url"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

// _CACertificatePrivateKeyOptions defines configuration options for generating a CA certificate and private key pair.
// This struct is used internally to configure the properties of a self-signed CA certificate.
//
// Fields:
//   - CommonName (string): Common Name (CN) for the certificate's subject, typically the CA's name (e.g., "Acme CA").
//   - Organization ([]string): Organization names included in the certificate's subject (e.g., ["Acme Co"]).
//   - ValidFrom (time.Time): The start time from which the certificate is valid. Defaults to the current time if not set.
//   - ValidFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365 days).
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

// _CacheEntry represents a cached TLS certificate and its creation time.
// This struct is used internally by CertificateAuthority to store dynamically generated certificates.
//
// Fields:
//   - certificate (*tls.Certificate): The cached TLS certificate, including the certificate chain and private key.
//   - createdAt (time.Time): The time when the certificate was created, used for cache expiration.
type _CacheEntry struct {
	certificate *tls.Certificate
	createdAt   time.Time
}

// CertificateAuthority represents a Certificate Authority (CA) for generating and signing TLS certificates.
// It encapsulates a CA certificate and its private key, providing methods to generate TLS configurations
// and certificates dynamically based on Server Name Indication (SNI) hostnames. Certificates are cached
// to improve performance, with configurable cache size and expiration.
//
// Fields:
//   - _CACertificate (*x509.Certificate): The X.509 CA certificate used to sign TLS certificates.
//   - _CAPrivateKey (crypto.Signer): The private key corresponding to the CA certificate, implementing crypto.Signer.
//   - cache (map[string]*_CacheEntry): A map storing cached TLS certificates, keyed by normalized hostname.
//   - cacheMutex (sync.RWMutex): A mutex for thread-safe access to the cache.
//   - cacheMaxAge (time.Duration): The maximum age of cached certificates before they expire (default: 1 hour).
//   - cacheMaxSize (int): The maximum number of certificates to store in the cache (default: 5).
type CertificateAuthority struct {
	_CACertificate *x509.Certificate
	_CAPrivateKey  crypto.Signer
	cache          map[string]*_CacheEntry
	cacheMutex     sync.RWMutex
	cacheMaxAge    time.Duration
	cacheMaxSize   int
}

// GenerateTLSCertificate generates a new X.509 TLS certificate and its corresponding private key.
//
// This method creates a private key (matching the CA's key type: RSA, ECDSA, or Ed25519) and a TLS certificate signed by the CA,
// based on the provided configuration options and hostnames. The certificate includes a random serial number, a subject key identifier (SKI),
// and supports key encipherment and digital signatures for server authentication. Hostnames are parsed to determine if they represent
// IP addresses, email addresses, URIs, or DNS names, and are added to the appropriate certificate fields.
//
// Parameters:
//   - hosts ([]string): A slice of hostnames (e.g., DNS names, IPs, emails, or URIs) to include in the certificate.
//   - ofs (...TLSCertificatePrivateKeyOptionFunc): A variadic list of TLSCertificatePrivateKeyOptionFunc functions to configure
//     the certificate's properties (e.g., CommonName, Organization, ValidFrom, ValidFor).
//
// Returns:
//   - TLSCertificate (*x509.Certificate): A pointer to the generated X.509 TLS certificate.
//   - TLSPrivateKey (crypto.Signer): The generated private key, implementing crypto.Signer.
//   - err (error): An error with stack trace and metadata if key generation, SKI generation, serial number generation,
//     certificate creation, or parsing fails; otherwise, nil.
func (CA *CertificateAuthority) GenerateTLSCertificate(hosts []string, ofs ...TLSCertificatePrivateKeyOptionFunc) (TLSCertificate *x509.Certificate, TLSPrivateKey crypto.Signer, err error) {
	if CA == nil {
		err = errors.New("invalid input, CertificateAuthority is nil")

		return
	}

	if len(hosts) == 0 {
		err = errors.New("invalid input, hosts list is empty")

		return
	}

	opts := &_TLSCertificatePrivateKeyOptions{
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

	if opts.CommonName == "" {
		err = errors.New("invalid input, CommonName is empty")

		return
	}

	if opts.ValidFor <= 0 {
		err = fmt.Errorf("invalid input, ValidFor duration must be positive, got %v", opts.ValidFor)

		return
	}

	switch caKey := CA._CAPrivateKey.(type) {
	case *rsa.PrivateKey:
		TLSPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			err = fmt.Errorf("failed to generate RSA private key (2048 bits): %w", err)

			return
		}
	case *ecdsa.PrivateKey:
		curve := caKey.Curve
		if curve == nil {
			curve = elliptic.P256()
		}

		TLSPrivateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = fmt.Errorf("failed to generate ECDSA private key (curve %v): %w", curve, err)

			return
		}
	case ed25519.PrivateKey:
		_, TLSPrivateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			err = fmt.Errorf("failed to generate Ed25519 private key: %w", err)

			return
		}
	default:
		err = fmt.Errorf("unsupported CA private key type: %T", caKey)

		return
	}

	TLSPublicKey := TLSPrivateKey.Public()

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = fmt.Errorf("failed to generate serial number for certificate: %w", err)

		return
	}

	var TLSPrivateKeySKI []byte

	TLSPrivateKeySKI, err = generateSubjectKeyID(TLSPublicKey)
	if err != nil {
		err = fmt.Errorf("failed to generate subject key ID for public key (type %T): %w", TLSPublicKey, err)

		return
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotBefore:    opts.ValidFrom.Add(-5 * time.Minute),
		NotAfter:     opts.ValidFrom.Add(opts.ValidFor),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: opts.Organization,
		},
		SubjectKeyId: TLSPrivateKeySKI,
	}

	for _, host := range hosts {
		if host == "" {
			err = errors.New("invalid input, empty hostname in hosts list")

			return
		}

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
		err = fmt.Errorf("failed to create TLS certificate for hosts %v: %w", hosts, err)

		return
	}

	TLSCertificate, err = x509.ParseCertificate(TLSCertificateInBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse generated TLS certificate: %w", err)

		return
	}

	return
}

// NewTLSConfig creates a TLS configuration for use in a TLS server.
//
// The configuration includes a dynamic certificate generation function based on Server Name Indication (SNI)
// and sets a minimum TLS version of TLS 1.2. It specifies supported cipher suites, curve preferences, and
// Application-Layer Protocol Negotiation (ALPN) protocols, including HTTP/1.0, HTTP/1.1, and HTTP/2.0.
//
// Returns:
//   - cfg (*tls.Config): A pointer to a tls.Config with a dynamic certificate generation function.
func (CA *CertificateAuthority) NewTLSConfig() (cfg *tls.Config) {
	cfg = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if CA == nil {
		return
	}

	cfg = &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		GetCertificate: CA.getTLSCertificateFunc(),
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	}

	return
}

// getTLSCertificateFunc returns a function to generate TLS certificates based on SNI.
//
// The returned function is used as the GetCertificate callback in a tls.Config. It generates or retrieves a cached
// TLS certificate for the provided server name (from SNI) with a short validity period (24 hours). Certificates are
// cached to improve performance, with expiration based on cacheMaxAge.
//
// Returns:
//   - (func(*tls.ClientHelloInfo) (*tls.Certificate, error)): A function that takes a tls.ClientHelloInfo and returns a tls.Certificate and an error.
//     The error includes stack trace and metadata if certificate generation fails or SNI is missing.
func (CA *CertificateAuthority) getTLSCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
		if hello == nil {
			err = errors.New("invalid input, ClientHelloInfo is nil")

			return
		}

		if hello.ServerName == "" {
			err = errors.New("invalid input, missing server name (SNI)")

			return
		}

		host := normalizeHost(hello.ServerName)

		CA.cacheMutex.RLock()

		if entry, exists := CA.cache[host]; exists {
			if time.Since(entry.createdAt) < CA.cacheMaxAge {
				certificate = entry.certificate

				CA.cacheMutex.RUnlock()

				return
			}

			CA.cacheMutex.RUnlock()
			CA.cacheMutex.Lock()

			delete(CA.cache, host)

			CA.cacheMutex.Unlock()

			return
		} else {
			CA.cacheMutex.RUnlock()
		}

		var TLSCertificate *x509.Certificate

		var TLSPrivateKey crypto.Signer

		TLSCertificate, TLSPrivateKey, err = CA.GenerateTLSCertificate([]string{host}, TLSCertificatePrivateKeyWithValidFor(24*time.Hour))
		if err != nil {
			err = fmt.Errorf("failed to generate TLS certificate for host '%s': %w", host, err)

			return
		}

		certificate = &tls.Certificate{
			Certificate: [][]byte{
				TLSCertificate.Raw,
				CA._CACertificate.Raw,
			},
			PrivateKey: TLSPrivateKey,
			Leaf:       TLSCertificate,
		}

		CA.cacheMutex.Lock()

		defer CA.cacheMutex.Unlock()

		if CA.cache == nil {
			CA.cache = make(map[string]*_CacheEntry)
		}

		if len(CA.cache) >= CA.cacheMaxSize {
			CA.clearOldCacheEntries()
		}

		CA.cache[host] = &_CacheEntry{
			certificate: certificate,
			createdAt:   time.Now(),
		}

		return
	}
}

// clearOldCacheEntries removes the oldest certificate from the cache to make room for new entries.
//
// It identifies the certificate with the earliest creation time and removes it from the cache.
// This is called when the cache reaches its maximum size (cacheMaxSize) to ensure the cache does not grow indefinitely.
func (CA *CertificateAuthority) clearOldCacheEntries() {
	var oldestKey string

	var oldestTime time.Time

	for key, entry := range CA.cache {
		if oldestTime.IsZero() || entry.createdAt.Before(oldestTime) {
			oldestTime = entry.createdAt
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(CA.cache, oldestKey)
	}
}

// _TLSCertificatePrivateKeyOptions defines configuration options for generating a TLS certificate and private key pair.
// This struct is used internally to configure the properties of a TLS certificate signed by the CA.
//
// Fields:
//   - CommonName (string): Common Name (CN) for the certificate's subject, typically the CA's name (e.g., "Acme CA").
//   - Organization ([]string): Organization names included in the certificate's subject (e.g., ["Acme Co"]).
//   - ValidFrom (time.Time): The start time from which the certificate is valid. Defaults to the current time if not set.
//   - ValidFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 365 days).
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
//   - opts (*_TLSCertificatePrivateKeyOptions): A pointer to _TLSCertificatePrivateKeyOptions to be modified.
type TLSCertificatePrivateKeyOptionFunc func(opts *_TLSCertificatePrivateKeyOptions)

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

// GenerateCACertificatePrivateKey generates a new X.509 CA certificate and its corresponding private key.
//
// This function creates a private key (RSA, ECDSA, or Ed25519 based on configuration) and a self-signed CA certificate
// using the functional options pattern. The certificate includes a random serial number, a subject key identifier (SKI),
// and is configured for certificate signing and CRL signing, as per RFC 5280. The validity period starts at ValidFrom
// (defaulting to the current time) and extends for ValidFor (defaulting to 365 days).
//
// Parameters:
//   - ofs (...CACertificatePrivateKeyOptionFunc): A variadic list of CACertificatePrivateKeyOptionFunc functions to configure
//     the certificate's properties (e.g., CommonName, Organization, ValidFrom, ValidFor).
//
// Returns:
//   - CACertificate (*x509.Certificate): A pointer to the generated X.509 CA certificate.
//   - CAPrivateKey (crypto.Signer): The generated private key, implementing crypto.Signer.
//   - err (error): An error with stack trace and metadata if key generation, SKI generation, serial number generation,
//     certificate creation, or parsing fails; otherwise, nil.
func GenerateCACertificatePrivateKey(ofs ...CACertificatePrivateKeyOptionFunc) (CACertificate *x509.Certificate, CAPrivateKey crypto.Signer, err error) {
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

	if opts.CommonName == "" {
		err = errors.New("invalid input, CommonName is empty")

		return
	}

	if opts.ValidFor <= 0 {
		err = fmt.Errorf("invalid input, ValidFor duration must be positive, got %v", opts.ValidFor)

		return
	}

	CAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate RSA private key (2048 bits): %w", err)

		return
	}

	CAPublicKey := CAPrivateKey.Public()

	var serialNumber *big.Int

	serialNumber, err = generateSerialNumber()
	if err != nil {
		err = fmt.Errorf("failed to generate serial number for CA certificate: %w", err)

		return
	}

	var CAPrivateKeySKI []byte

	CAPrivateKeySKI, err = generateSubjectKeyID(CAPublicKey)
	if err != nil {
		err = fmt.Errorf("failed to generate subject key ID for public key (type %T): %w", CAPublicKey, err)

		return
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             opts.ValidFrom.Add(-5 * time.Minute),
		NotAfter:              opts.ValidFrom.Add(opts.ValidFor),
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		SubjectKeyId: CAPrivateKeySKI,
	}

	var CACertificateInBytes []byte

	CACertificateInBytes, err = x509.CreateCertificate(rand.Reader, template, template, CAPublicKey, CAPrivateKey)
	if err != nil {
		err = fmt.Errorf("failed to create self-signed CA certificate: %w", err)

		return
	}

	CACertificate, err = x509.ParseCertificate(CACertificateInBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse generated CA certificate: %w", err)

		return
	}

	return
}

// GenerateCACertificatePrivateKeyBytes generates a new X.509 CA certificate and private key, returning them in PEM format.
//
// This function wraps GenerateCACertificatePrivateKey and converts the resulting certificate and private key to PEM format.
//
// Parameters:
//   - ofs (...CACertificatePrivateKeyOptionFunc): A variadic list of CACertificatePrivateKeyOptionFunc functions to configure
//     the certificate's properties (e.g., CommonName, Organization, ValidFrom, ValidFor).
//
// Returns:
//   - CACertificateBytes ([]byte): The PEM-encoded CA certificate.
//   - CAPrivateKeyBytes ([]byte): The PEM-encoded private key.
//   - err (error): An error with stack trace and metadata if generation or PEM encoding fails; otherwise, nil.
func GenerateCACertificatePrivateKeyBytes(ofs ...CACertificatePrivateKeyOptionFunc) (CACertificateBytes, CAPrivateKeyBytes []byte, err error) {
	var CACertificate *x509.Certificate

	var CAPrivateKey crypto.Signer

	CACertificate, CAPrivateKey, err = GenerateCACertificatePrivateKey(ofs...)
	if err != nil {
		err = fmt.Errorf("failed to generate CA certificate and private key: %w", err)

		return
	}

	CACertificateBytes, err = CertificateToPEM(CACertificate)
	if err != nil {
		err = fmt.Errorf("failed to convert CA certificate to PEM format: %w", err)

		return
	}

	CAPrivateKeyBytes, err = PrivateKeyToPEM(CAPrivateKey)
	if err != nil {
		err = fmt.Errorf("failed to convert CA private key to PEM format (type %T): %w", CAPrivateKey, err)

		return
	}

	return
}

// CertificateToPEM converts an X.509 certificate to PEM format.
//
// The certificate is encoded as a PEM block with type "CERTIFICATE", as per RFC 7468. The resulting PEM data
// is returned as a byte slice for further use (e.g., writing to a file or network).
//
// Parameters:
//   - certificate (*x509.Certificate): A pointer to the X.509 certificate to convert.
//
// Returns:
//   - raw ([]byte): A byte slice containing the PEM-encoded certificate.
//   - err (error): An error with stack trace and metadata if PEM encoding fails or the certificate is nil; otherwise, nil.
func CertificateToPEM(certificate *x509.Certificate) (raw []byte, err error) {
	if certificate == nil {
		err = errors.New("invalid input, certificate is nil")

		return
	}

	if len(certificate.Raw) == 0 {
		err = errors.New("invalid input, certificate raw data is empty")

		return
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}

	if raw = pem.EncodeToMemory(block); raw == nil {
		err = errors.New("failed to encode certificate to PEM format")

		return
	}

	return
}

// PrivateKeyToPEM converts a private key to PEM format.
//
// The private key is marshaled to the appropriate format (PKCS#1 for RSA, EC for ECDSA, PKCS#8 for Ed25519) and encoded
// as a PEM block with type "RSA PRIVATE KEY", "EC PRIVATE KEY", or "PRIVATE KEY", as per RFC 7468. The resulting PEM data
// is returned as a byte slice.
//
// Parameters:
//   - key (crypto.Signer): The private key to convert, implementing crypto.Signer.
//
// Returns:
//   - raw ([]byte): A byte slice containing the PEM-encoded private key.
//   - err (error): An error with stack trace and metadata if marshaling or PEM encoding fails, or if the key is nil or unsupported; otherwise, nil.
func PrivateKeyToPEM(key crypto.Signer) (raw []byte, err error) {
	if key == nil {
		err = errors.New("invalid input, private key is nil")

		return
	}

	var blockType string

	var keyBytes []byte

	switch k := key.(type) {
	case *rsa.PrivateKey:
		blockType = "RSA PRIVATE KEY"

		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		if keyBytes == nil {
			err = errors.New("failed to marshal RSA private key, empty result")

			return
		}
	case *ecdsa.PrivateKey:
		blockType = "EC PRIVATE KEY"

		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			err = fmt.Errorf("failed to marshal ECDSA private key: %w", err)

			return
		}
	case ed25519.PrivateKey:
		blockType = "PRIVATE KEY"

		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			err = fmt.Errorf("failed to marshal Ed25519 private key: %w", err)

			return
		}
	default:
		err = fmt.Errorf("unsupported private key type: %T", key)

		return
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	if raw = pem.EncodeToMemory(block); raw == nil {
		err = fmt.Errorf("failed to encode private key to PEM format (type %s)", blockType)

		return
	}

	return
}

// TLSCertificatePrivateKeyWithCommonName sets the Common Name (CN) for the TLS certificate's subject.
//
// Parameters:
//   - commonName (string): The Common Name to set in the certificate's subject (e.g., "example.com").
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
//   - organization ([]string): A slice of organization names to set in the certificate's subject (e.g., ["My Org"]).
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
//   - validFor (time.Duration): The duration for which the certificate is valid from ValidFrom (e.g., 24*time.Hour).
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
// signing. The private key must match the public key type in the certificate (RSA, ECDSA, or Ed25519).
// The cache is initialized with a default maximum age of 1 hour.
//
// Parameters:
//   - CACertificate (*x509.Certificate): A pointer to the X.509 CA certificate.
//   - CAPrivateKey (crypto.Signer): The private key corresponding to the CA certificate, implementing crypto.Signer.
//
// Returns:
//   - CA (*CertificateAuthority): A pointer to the initialized CertificateAuthority.
//   - err (error): An error with stack trace and metadata if the CA certificate or private key is invalid or incompatible; otherwise, nil.
func New(CACertificate *x509.Certificate, CAPrivateKey crypto.Signer) (CA *CertificateAuthority, err error) {
	if CACertificate == nil {
		err = errors.New("invalid input, CA certificate is nil")

		return
	}

	if !CACertificate.IsCA {
		err = errors.New("invalid input, certificate is not configured as a CA (IsCA is false)")

		return
	}

	if (CACertificate.KeyUsage & x509.KeyUsageCertSign) == 0 {
		err = errors.New("invalid input, CA certificate lacks KeyUsageCertSign")

		return
	}

	if CAPrivateKey == nil {
		err = errors.New("invalid input, CA private key is nil")

		return
	}

	switch pubKey := CACertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if _, ok := CAPrivateKey.(*rsa.PrivateKey); !ok {
			err = fmt.Errorf("invalid input, certificate public key is RSA, but private key is %T", CAPrivateKey)

			return
		}
	case *ecdsa.PublicKey:
		if _, ok := CAPrivateKey.(*ecdsa.PrivateKey); !ok {
			err = fmt.Errorf("invalid input, certificate public key is ECDSA, but private key is %T", CAPrivateKey)

			return
		}
	case ed25519.PublicKey:
		if _, ok := CAPrivateKey.(ed25519.PrivateKey); !ok {
			err = fmt.Errorf("invalid input, certificate public key is Ed25519, but private key is %T", CAPrivateKey)

			return
		}
	default:
		err = fmt.Errorf("unsupported certificate public key type: %T", pubKey)

		return
	}

	CA = &CertificateAuthority{
		_CACertificate: CACertificate,
		_CAPrivateKey:  CAPrivateKey,
		cache:          make(map[string]*_CacheEntry),
		cacheMutex:     sync.RWMutex{},
		cacheMaxAge:    1 * time.Hour,
		cacheMaxSize:   5,
	}

	return
}

// NewWithBytesCertificatePrivateKey initializes a new CertificateAuthority from PEM-encoded certificate and private key bytes.
//
// It parses the certificate and private key from the provided byte slices, supporting PKCS#1, PKCS#8, and ECDSA private key formats.
// The parsed certificate and private key are then used to initialize a CertificateAuthority.
//
// Parameters:
//   - CACertificateBytes ([]byte): The PEM-encoded CA certificate bytes.
//   - CAPrivateKeyBytes ([]byte): The PEM-encoded private key bytes.
//
// Returns:
//   - CA (*CertificateAuthority): A pointer to the initialized CertificateAuthority.
//   - err (error): An error with stack trace and metadata if parsing or initialization fails; otherwise, nil.
func NewWithBytesCertificatePrivateKey(CACertificateBytes, CAPrivateKeyBytes []byte) (CA *CertificateAuthority, err error) {
	if len(CACertificateBytes) == 0 {
		err = errors.New("invalid input, CA certificate bytes are empty")

		return
	}

	if len(CAPrivateKeyBytes) == 0 {
		err = errors.New("invalid input, CA private key bytes are empty")

		return
	}

	certBlock, _ := pem.Decode(CACertificateBytes)
	if certBlock == nil {
		err = errors.New("failed to decode PEM block for CA certificate, invalid or malformed PEM data")

		return
	}

	if certBlock.Type != "CERTIFICATE" {
		err = fmt.Errorf("invalid PEM block type for CA certificate: got '%s', expected 'CERTIFICATE'", certBlock.Type)

		return
	}

	var CACertificate *x509.Certificate

	CACertificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse X.509 certificate from PEM data: %w", err)

		return
	}

	keyBlock, _ := pem.Decode(CAPrivateKeyBytes)
	if keyBlock == nil {
		err = errors.New("failed to decode PEM block for private key, invalid or malformed PEM data")

		return
	}

	var CAPrivateKey crypto.Signer

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		var key *rsa.PrivateKey

		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			err = fmt.Errorf("failed to parse RSA private key from PEM data: %w", err)

			return
		}

		CAPrivateKey = key
	case "EC PRIVATE KEY":
		var key *ecdsa.PrivateKey

		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			err = fmt.Errorf("failed to parse ECDSA private key from PEM data: %w", err)

			return
		}

		CAPrivateKey = key
	case "PRIVATE KEY":
		var key any

		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			err = fmt.Errorf("failed to parse PKCS#8 private key from PEM data: %w", err)

			return
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			err = fmt.Errorf("private key of type %T does not implement crypto.Signer", key)

			return
		}

		CAPrivateKey = signer
	default:
		err = fmt.Errorf("unsupported PEM block type for private key: got '%s', expected 'RSA PRIVATE KEY', 'EC PRIVATE KEY', or 'PRIVATE KEY'", keyBlock.Type)

		return
	}

	return New(CACertificate, CAPrivateKey)
}

// generateSerialNumber creates a random serial number for use in X.509 certificates.
//
// Serial numbers are unique identifiers for certificates, as required by RFC 5280. This function generates a
// cryptographically secure random number with a maximum bit length of 128 bits, ensuring compliance with common
// certificate authority requirements. If the generated number is zero, it defaults to 1 to avoid invalid serial numbers.
//
// Returns:
//   - serialNumber (*big.Int): A pointer to a big.Int representing the generated serial number.
//   - err (error): An error with stack trace and metadata if random number generation fails; otherwise, nil.
func generateSerialNumber() (serialNumber *big.Int, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = fmt.Errorf("failed to generate random serial number (128-bit): %w", err)

		return
	}

	if serialNumber.Sign() == 0 {
		serialNumber = big.NewInt(1)
	}

	return
}

// generateSubjectKeyID computes a Subject Key Identifier (SKI) from a given public key.
//
// The Subject Key Identifier is a SHA-256 hash of the public key's PKIX-encoded form, as specified in RFC 5280,
// section 4.2.1.2. It is used to uniquely identify a public key in an X.509 certificate.
//
// Parameters:
//   - publicKey (crypto.PublicKey): The cryptographic public key (e.g., *rsa.PublicKey) to generate the SKI for.
//
// Returns:
//   - SKI ([]byte): A byte slice containing the SHA-256 hash of the marshaled public key.
//   - err (error): An error with stack trace and metadata if public key marshaling fails or the key is empty; otherwise, nil.
func generateSubjectKeyID(publicKey crypto.PublicKey) (SKI []byte, err error) {
	if publicKey == nil {
		err = errors.New("invalid input, public key is nil")

		return
	}

	pkixPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		err = fmt.Errorf("failed to marshal public key (type %T) to PKIX format: %w", publicKey, err)

		return
	}

	if len(pkixPub) == 0 {
		err = fmt.Errorf("invalid public key (type %T), marshaled PKIX data is empty", publicKey)

		return
	}

	sum := sha256.Sum256(pkixPub)

	SKI = sum[:]

	return
}

// normalizeHost normalizes a hostname by removing the port number and applying Unicode NFC normalization.
//
// It splits the hostname using net.SplitHostPort to remove any port component and applies Unicode NFC normalization
// to ensure consistent hostname representation, as recommended by RFC 3986 for URIs.
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

	normalized = norm.NFC.String(normalized)

	return
}
