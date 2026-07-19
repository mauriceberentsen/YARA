package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEd25519PEMKeysAndRejectUnsafePrivatePermissions(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	privateDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	privatePath, publicPath := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	loadedPrivate, err := LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedPrivate.Equal(privateKey) || !loadedPublic.Equal(publicKey) {
		t.Fatal("loaded keys differ")
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(privatePath); err == nil {
		t.Fatal("unsafe private key permissions accepted")
	}
}
