package main

// Enkripsi arsip v3: AES-256-GCM (AEAD) dengan kunci dari Argon2id.
// Yang dienkripsi: setiap segmen grup DAN segmen index (nama file ikut
// tersembunyi, seperti RAR -hp). Footer tetap polos (hanya offset index).
// Password tidak pernah disimpan di arsip maupun dicetak.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemKiB  uint32 = 64 * 1024
	argonThreads uint32 = 4
	saltLen             = 16
	gcmNonceLen         = 12
)

type cryptoCtx struct {
	key []byte
}

func deriveKey(password string, salt []byte, t, memKiB, threads uint32) []byte {
	return argon2.IDKey([]byte(password), salt, t, memKiB, uint8(threads), 32)
}

func newWriteCrypto(password string) (*cryptoCtx, []byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key := deriveKey(password, salt, argonTime, argonMemKiB, argonThreads)
	return &cryptoCtx{key: key}, salt, nil
}

func newReadCrypto(password string, salt []byte, t, memKiB, threads uint32) *cryptoCtx {
	return &cryptoCtx{key: deriveKey(password, salt, t, memKiB, threads)}
}

// seal mengenkripsi plain, hasil = [12 nonce][ciphertext+tag].
func (c *cryptoCtx) seal(plain []byte) ([]byte, error) {
	gcm, err := newGCM(c.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// open membalik seal; gagal bila password salah atau data diubah (tag GCM).
func (c *cryptoCtx) open(data []byte) ([]byte, error) {
	gcm, err := newGCM(c.key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcmNonceLen {
		return nil, errors.New("data terenkripsi terlalu pendek")
	}
	plain, err := gcm.Open(nil, data[:gcmNonceLen], data[gcmNonceLen:], nil)
	if err != nil {
		return nil, errors.New("gagal membuka enkripsi (password salah atau arsip rusak)")
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
