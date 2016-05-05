package aesctr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// Test Cipher Encrypt and Decrypt of large input.
func TestCipherEncryptDecrypt(t *testing.T) {
	key := []byte("thisIsJustARandomStringOfChars=)")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Could not create cipher: %v", err)
	}

	plaintext := make([]byte, 10*1024*1024)
	for i := 0; i < len(plaintext); i++ {
		plaintext[i] = byte(i % 256)
	}

	iv := make([]byte, block.BlockSize())
	for i := 0; i < len(iv); i++ {
		iv[i] = byte(i)
	}

	encrypter := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	encrypter.XORKeyStream(ciphertext, plaintext)

	bReader := bytes.NewReader(ciphertext)
	decrypter := NewCTRReaderAt(block, iv, bReader)

	chunk := make([]byte, 1024)
	for i := 0; i < (len(plaintext)/257)-5; i++ {
		offset := i * 257
		decrypter.ReadAt(chunk, int64(offset))
		for j := 0; j < len(chunk); j++ {
			if chunk[j] != plaintext[offset+j] {
				t.Fatalf("Decrypted chunk does not match")
			}
		}
	}

}
