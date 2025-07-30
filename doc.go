// Package tls provides utilities for generating and managing TLS-related cryptographic
// artifacts, such as X.509 Certificate Authority (CA) certificates, private keys, and
// dynamically generated TLS certificates for secure server communication.
//
// The package is designed to simplify the creation and management of a CA, enabling the generation
// of signed TLS certificates for specific hostnames via Server Name Indication (SNI).
// It integrates robust error handling using the hq-go-errors package, providing detailed
// stack traces, error classification, and structured metadata for debugging.
//
// Example Usage:
//
// Below is an example demonstrating how to generate a CA certificate, initialize a CertificateAuthority,
// and configure a TLS server with dynamic certificate generation.
//
// ```go
// package main
//
// import (
//
//	"crypto/tls"
//	"fmt"
//	"log"
//	"net/http"
//	"time"
//
//	hqgotls "github.com/hueristiq/hq-go-tls"
//	hqgoerrors "github.com/hueristiq/hq-go-errors"
//
// )
//
//	func main() {
//		// Define CA certificate options
//		caOptions := &hqgotls.CACertificatePrivateKeyOptions{
//			CommonName:   "MyCA",
//			Organization: []string{"Example Org"},
//			Validity:     365 * 24 * time.Hour,
//		}
//
//		// Generate CA certificate and private key
//		caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(caOptions)
//		if err != nil {
//			log.Fatalf("Failed to generate CA: %s", hqgoerrors.ToString(err, true))
//		}
//
//		// Save CA certificate and private key to files
//		if err := hqgotls.SaveCACertificatePrivateKey(caCert, "ca-cert.pem", caKey, "ca-key.pem"); err != nil {
//			log.Fatalf("Failed to save CA: %s", hqgoerrors.ToString(err, true))
//		}
//
//		// Initialize CertificateAuthority
//		ca, err := hqgotls.New(caCert, caKey)
//		if err != nil {
//			log.Fatalf("Failed to initialize CA: %s", hqgoerrors.ToString(err, true))
//		}
//
//		// Create TLS configuration
//		tlsConfig := ca.NewTLSConfig()
//
//		// Set up an HTTP server with TLS
//		server := &http.Server{
//			Addr:      ":8443",
//			TLSConfig: tlsConfig,
//			Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//				fmt.Fprintf(w, "Hello, TLS from %s!", r.Host)
//			}),
//		}
//
//		// Start the server
//		log.Printf("Starting TLS server on :8443")
//		if err := server.ListenAndServeTLS("", ""); err != nil {
//			log.Fatalf("Server failed: %v", err)
//		}
//	}
//
// ```
package tls
