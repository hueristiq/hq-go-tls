# hq-go-tls

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go report card](https://goreportcard.com/badge/github.com/hueristiq/hq-go-tls)](https://goreportcard.com/report/github.com/hueristiq/hq-go-tls) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-go-tls/blob/master/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-go-tls.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-go-tls/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-go-tls.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-go-tls/issues?q=is:issue+is:closed) [![contribution](https://img.shields.io/badge/contributions-welcome-1E90FF.svg)](https://github.com/hueristiq/hq-go-tls/blob/master/CONTRIBUTING.md)

`hq-go-tls` is a [Go (Golang)](http://golang.org/) package for generating, managing, and signing X.509 certificates. It provides a robust API for creating self-signed Certificate Authority (CA) certificates, issuing TLS certificates for various host types, and configuring TLS servers with dynamic certificate generation based on Server Name Indication (SNI).

## Resource

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
	- [Generating a CA Certificate](#generating-a-ca-certificate)
	- [Loading a CA Certificate](#loading-a-ca-certificate)
	- [Generating a TLS Certificate](#generating-a-tls-certificate)
	- [Configuring a TLS Server with SNI](#configuring-a-tls-server-with-sni)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Features

- **Self-Signed CA Certificate Generation:** Create CA certificates with customizable attributes.
- **TLS Certificate Issuance:** Generate signed TLS certificates supporting multiple host types (DNS names, IP addresses, email addresses, URIs) with configurable properties.
- **Dynamic TLS Configuration:** Support for SNI-based certificate generation in TLS servers, with a minimum TLS version of 1.2, secure cipher suites, and ALPN protocols (HTTP/1.1, HTTP/2.0, HTTP/3.0).
- **Certificate Caching:** In-memory caching of dynamically generated certificates to optimize performance, with configurable cache size and expiration.
- **Standards Compliance:** Adheres to RFC 5280 for certificate generation and RFC 7468 for PEM encoding, ensuring compatibility with standard TLS implementations.

## Installation

To install `hq-go-tls`, run:

```bash
go get -v -u github.com/hueristiq/hq-go-tls
```

Make sure your Go environment is set up properly (Go 1.x or later is recommended).

## Usage

### Generating a CA Certificate

Use `GenerateCACertificatePrivateKey` to create a self-signed CA certificate and RSA private key. Save it to PEM files with `SaveCertificatePrivateKey`.

```go
package main

import (
	"log"
	"time"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	// Generate a CA certificate with custom options
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
		hqgotls.CACertificatePrivateKeyWithCommonName("My Root CA"),
		hqgotls.CACertificatePrivateKeyWithOrganization([]string{"My Company"}),
		hqgotls.CACertificatePrivateKeyWithValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Save to PEM files
	if err = hqgotls.SaveCertificatePrivateKeyToFiles(caCert, "ca-cert.pem", caKey, "ca-key.pem"); err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}

	log.Println("CA certificate and key saved to ca-cert.pem and ca-key.pem")
}
```

### Loading a Certificate

Load a certificate and private key from PEM files using `LoadCertificatePrivateKeyFromFiles`.

```go
package main

import (
	"log"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	// Load CA certificate and private key
	caCert, caKey, err := hqgotls.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	log.Println("Successfully loaded CA certificate and key")
}
```

### Generating a TLS Certificate

Use a `CertificateAuthority` to issue a TLS certificate for specific hosts, supporting DNS names, IP addresses, email addresses, or URIs.

```go
package main

import (
	"log"
	"time"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	// Load CA certificate and private key
	caCert, caKey, err := hqgotls.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize CertificateAuthority
	ca, err := hqgotls.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Generate TLS certificate for multiple hosts
	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "www.example.com", "192.168.1.1", "user@example.com"},
		hqgotls.TLSCertificatePrivateKeyWithCommonName("example.com"),
		hqgotls.TLSCertificatePrivateKeyWithOrganization([]string{"My Company"}),
		hqgotls.TLSCertificatePrivateKeyWithValidFor(30*24*time.Hour), // 30 days
	)
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Save TLS certificate and key
	if err := hqgotls.SaveCertificatePrivateKeyToFiles(tlsCert, "tls-cert.pem", tlsKey, "tls-key.pem"); err != nil {
		log.Fatalf("Failed to save TLS certificate: %v", err)
	}

	log.Println("TLS certificate and key saved to tls-cert.pem and tls-key.pem")
}
```

### Configuring a TLS Server with SNI

Configure an HTTP server with a `tls.Config` that dynamically generates certificates based on the SNI hostname provided by the client.

```go
package main

import (
	"log"
	"net/http"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	// Generate or load CA certificate and key
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Initialize CertificateAuthority
	ca, err := hqgotls.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Create TLS configuration with SNI support
	tlsConfig := ca.NewTLSConfig()

	// Configure HTTP server
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS with SNI!"))
		}),
	}

	log.Println("Starting TLS server on :443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-go-tls/pulls) or report [Issues](https://github.com/hueristiq/hq-go-tls/issues). For more details, check out the [contribution guidelines](https://github.com/hueristiq/hq-go-tls/blob/master/CONTRIBUTING.md).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-go-tls/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-go-tls&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-go-tls/blob/master/LICENSE).