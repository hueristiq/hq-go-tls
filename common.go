package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"math/big"

	hqgoerrors "github.com/hueristiq/hq-go-errors"
)

// generateSerialNumber creates a random serial number for use in X.509 certificates.
//
// Serial numbers are unique identifiers for certificates, as required by the X.509 standard.
// This function generates a cryptographically secure random number with a maximum bit length
// of 128 bits, ensuring compliance with common certificate authority requirements.
// If the generated number is zero, it defaults to 1 to avoid invalid serial numbers.
//
// Returns:
//   - serialNumber (*big.Int): A pointer to a big.Int representing the generated serial number.
//   - err (error): An error if the random number generation fails; otherwise, nil.
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
// The Subject Key Identifier is a SHA-1 hash of the public key's PKIX-encoded form,
// as specified in RFC 5280, section 4.2.1.2. It is used to uniquely identify a public key
// in an X.509 certificate. If the public key cannot be marshaled or is empty, an error is returned.
//
// Parameters:
//   - pubKey (crypto.PublicKey): The cryptographic public key to generate the SKI for.
//
// Returns:
//   - SKI ([]byte): A byte slice containing the SHA-1 hash of the marshaled public key.
//   - err (error): An error if the public key marshaling fails or the key is empty; otherwise, nil.
func generateSubjectKeyID(pubKey crypto.PublicKey) (SKI []byte, err error) {
	pkixPub, err := x509.MarshalPKIXPublicKey(pubKey)
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
