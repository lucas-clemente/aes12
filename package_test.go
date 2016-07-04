package aes12_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/lucas-clemente/aes12"
)

const plaintextLen = 1000

var (
	key       []byte
	nonce     []byte
	aad       []byte
	plaintext []byte
)

func init() {
	key = make([]byte, 32)
	rand.Read(key)
	nonce = make([]byte, 12)
	rand.Read(nonce)
	aad = make([]byte, 42)
	rand.Read(aad)
	plaintext = make([]byte, plaintextLen)
	rand.Read(plaintext)
}

func TestEncryption(t *testing.T) {
	cipher, err := aes12.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	gcm, err := aes12.NewGCM(cipher)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	if len(ciphertext) != plaintextLen+12 {
		t.Fatal("expected ciphertext to have len(plaintext)+12")
	}

	decrypted, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decryption yielded unexpected result")
	}
}
