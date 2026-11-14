package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// sctSigner signs RFC 6962 SCTs as a log that doesn't exist.
type sctSigner struct {
	key   *ecdsa.PrivateKey
	spki  []byte
	logID [sha256.Size]byte
}

// loadSCTSigner reads the ECDSA P-256 key in the PKCS #8 PEM file at path,
// generating it if the file doesn't exist.
func loadSCTSigner(path string) (s *sctSigner, created bool, err error) {
	pemBytes, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, false, err
		}
		pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, false, err
		}
		if _, err := f.Write(pemBytes); err != nil {
			f.Close()
			return nil, false, err
		}
		if err := f.Close(); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, false, errors.New("not a PRIVATE KEY PEM file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, false, errors.New("not an ECDSA P-256 key")
	}
	s, err = newSCTSigner(key)
	return s, created, err
}

func newSCTSigner(key *ecdsa.PrivateKey) (*sctSigner, error) {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &sctSigner{key: key, spki: spki, logID: sha256.Sum256(spki)}, nil
}

// LogID returns the base64 encoding of the log ID, the hash of the public key.
func (s *sctSigner) LogID() string {
	return base64.StdEncoding.EncodeToString(s.logID[:])
}

// PublicKey returns the base64 encoding of the SubjectPublicKeyInfo, which is
// how log lists represent log keys.
func (s *sctSigner) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.spki)
}

// addChainResponse is the output of add-chain (RFC 6962, Section 4.1).
type addChainResponse struct {
	SCTVersion int    `json:"sct_version"`
	ID         []byte `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  []byte `json:"signature"`
}

// Sign returns a v1 SCT with no extensions for an X.509 entry (RFC 6962,
// Section 3.2), where cert is the DER encoding of the certificate.
func (s *sctSigner) Sign(cert []byte, t time.Time) (*addChainResponse, error) {
	timestamp := t.UnixMilli()

	b := cryptobyte.NewBuilder(make([]byte, 0, len(cert)+20))
	b.AddUint8(0) // sct_version = v1
	b.AddUint8(0) // signature_type = certificate_timestamp
	b.AddUint64(uint64(timestamp))
	b.AddUint16(0) // entry_type = x509_entry
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cert) })
	b.AddUint16(0) // extensions
	input, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding SCT signature input: %w", err)
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}

	// DigitallySigned (RFC 5246, Section 4.7).
	b = cryptobyte.NewBuilder(make([]byte, 0, len(sig)+4))
	b.AddUint8(4) // HashAlgorithm = sha256
	b.AddUint8(3) // SignatureAlgorithm = ecdsa
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sig) })
	signature, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding SCT signature: %w", err)
	}

	return &addChainResponse{
		SCTVersion: 0,
		ID:         s.logID[:],
		Timestamp:  timestamp,
		Signature:  signature,
	}, nil
}
