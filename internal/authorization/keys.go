// Package authorization contains cryptographic boundary helpers for short-lived
// execution capabilities. It never generates or stores private keys.
package authorization

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("authorization private key is unavailable")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("authorization private key must not be group/world accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("authorization private key is unavailable")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("authorization private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("authorization private key is not PKCS#8")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("authorization private key is not Ed25519")
	}
	return key, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("trusted authorization public key is unavailable")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("trusted authorization public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("trusted authorization public key is not PKIX")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted authorization public key is not Ed25519")
	}
	return key, nil
}
