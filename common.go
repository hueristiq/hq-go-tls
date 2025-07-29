package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
)

func generateSerialNumber() (serialNumber *big.Int, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	return
}

func generateSubjectKeyID(publicKey crypto.PublicKey) (keyID []byte, err error) {
	pkixPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}

	hash := sha256.New()

	hash.Write(pkixPub)

	keyID = hash.Sum(nil)

	return
}
