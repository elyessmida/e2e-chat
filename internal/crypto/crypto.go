// Package crypto provides all cryptographic primitives used by e2e-chat:
//
//   - X25519 ephemeral key-pair generation
//   - HKDF-SHA256 shared-key derivation from a raw DH secret
//   - AES-256-GCM authenticated encryption / decryption
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	gocrypto "crypto"
	_ "crypto/sha256" // register SHA-256 for hkdf
)

// hkdfInfo is the fixed context string used in HKDF so that keys derived for
// this application are domain-separated from any other potential use of the
// same DH secret.
const hkdfInfo = "e2e-chat-aes-key"

// NonceSize is the AES-GCM nonce length (12 bytes as required by GCM).
const NonceSize = 12

// KeyPair holds an X25519 ephemeral key pair.
type KeyPair struct {
	Private [32]byte // scalar (private key)
	Public  [32]byte // curve point (public key)
}

// GenerateKeyPair creates a fresh X25519 ephemeral key pair using
// crypto/rand as the entropy source.
func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair

	// Generate 32 random bytes for the private scalar.
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, fmt.Errorf("crypto: generate private key: %w", err)
	}

	// Clamp the private scalar as required by X25519.
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	// Derive the public key: public = private * G (base point).
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive public key: %w", err)
	}
	copy(kp.Public[:], pub)
	return &kp, nil
}

// DeriveSharedKey performs X25519(myPrivate, peerPublic) and then runs
// HKDF-SHA256 over the raw DH output to produce a 32-byte AES-256 key.
//
// Using HKDF instead of the raw DH output is important because raw DH output
// is not uniformly random and should never be used directly as a symmetric key.
func DeriveSharedKey(myPrivate, peerPublic [32]byte) ([32]byte, error) {
	// X25519 Diffie-Hellman.
	dhSecret, err := curve25519.X25519(myPrivate[:], peerPublic[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("crypto: X25519: %w", err)
	}

	// HKDF-SHA256: extract + expand into a 32-byte key.
	// salt = nil  (uses HKDF's zero-salt default, which is fine here because
	// the DH output already provides good randomness).
	hkdfReader := hkdf.New(gocrypto.SHA256.New, dhSecret, nil, []byte(hkdfInfo))
	var key [32]byte
	if _, err := io.ReadFull(hkdfReader, key[:]); err != nil {
		return [32]byte{}, fmt.Errorf("crypto: HKDF expand: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// It prepends a freshly generated random 12-byte nonce to the ciphertext.
//
// Returned format: [12-byte nonce] [ciphertext + 16-byte GCM tag]
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM: %w", err)
	}

	// Generate a fresh random nonce for every message.
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}

	// Seal appends the ciphertext (+ tag) after nonce in the output slice.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a message produced by Encrypt.
// It expects the first 12 bytes to be the nonce.
func Decrypt(key [32]byte, data []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM: %w", err)
	}

	nonce, ciphertext := data[:NonceSize], data[NonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
