# hq-go-tls

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go report card](https://goreportcard.com/badge/github.com/hueristiq/hq-go-tls)](https://goreportcard.com/report/github.com/hueristiq/hq-go-tls) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-go-tls/blob/master/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-go-tls.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-go-tls/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-go-tls.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-go-tls/issues?q=is:issue+is:closed) [![contribution](https://img.shields.io/badge/contributions-welcome-1E90FF.svg)](https://github.com/hueristiq/hq-go-tls/blob/master/CONTRIBUTING.md)

`hq-go-tls` is a [Go (Golang)](http://golang.org/) package for for generating, managing, and signing X.509 certificates. It supports creating self-signed Certificate Authority (CA) certificates, issuing TLS certificates, and configuring TLS servers with dynamic certificate generation based on Server Name Indication (SNI).

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

- **CA Certificate Generation:** Create self-signed CA certificates with configurable properties.
- **TLS Certificate Issuance:** Generate signed TLS certificates for multiple host types (DNS names, IPs, emails, URIs) with customizable attributes.
- **Dynamic TLS Configuration:** Support SNI-based certificate generation for TLS servers, with a minimum TLS version of 1.2 and ALPN protocols (HTTP/1.0, HTTP/1.1, HTTP/2.0).

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
	// Generate CA certificate
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
		hqgotls.CACertificatePrivateKeyWithCommonName("My Root CA"),
		hqgotls.CACertificatePrivateKeyWithOrganization([]string{"My Company"}),
		hqgotls.CACertificatePrivateKeyWithValidFor(2*365*24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Save to files
	err = hqgotls.SaveCertificatePrivateKey(caCert, "ca-cert.pem", caKey, "ca-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
```

### Loading a CA Certificate

Load a CA certificate and private key from PEM files using `LoadCACertificatePrivateKey`.

```go
caCert, caKey, err := hqgotls.LoadCACertificatePrivateKey("ca-cert.pem", "ca-key.pem")
if err != nil {
	log.Fatal(err)
}
```

### Generating a TLS Certificate

```go
package main

import (
	"log"
	"time"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	caCert, caKey, err := hqgotls.LoadCACertificatePrivateKey("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	ca, err := tls.New(caCert, caKey)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "192.168.1.1", "user@example.com"},
		tls.TLSCertificatePrivateKeyWithCommonName("example.com"),
		tls.TLSCertificatePrivateKeyWithValidFor(30*24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Save to files
	err = tls.SaveCertificatePrivateKey(tlsCert, "tls-cert.pem", tlsKey, "tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
```

### Configuring a TLS Server with SNI

Create a `tls.Config` for a server that dynamically generates certificates based on SNI.

```go
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	hqgotls "github.com/hueristiq/hq-go-tls"
)

func main() {
	// Generate and initialize CA
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	ca, err := hqgotls.New(caCert, caKey)
	if err != nil {
		log.Fatal(err)
	}

	// Create TLS config
	tlsConfig := ca.NewTLSConfig()

	// Set up HTTP server
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS!"))
		}),
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
```

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-go-tls/pulls) or report [Issues](https://github.com/hueristiq/hq-go-tls/issues). For more details, check out the [contribution guidelines](https://github.com/hueristiq/hq-go-tls/blob/master/CONTRIBUTING.md).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-go-tls/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-go-tls&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-go-tls/blob/master/LICENSE).