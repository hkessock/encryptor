package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

type CipherEnum uint8
type CipherModeEnum uint8

const (
	AES CipherEnum = iota
)

const (
	GCM CipherModeEnum = iota
)

const AESNonceSize uint = 12
const AESTagSize uint = 16

func generateKey256FromString(keyMaterial string) ([]byte, error) {

	// OWASP recommends north of 300,000 iterations of hashing if I recall correctly
	key := pbkdf2.Key([]byte(keyMaterial), nil, 350000, 32, sha256.New)

	if len(key) == 32 {
		return key, nil
	}

	return []byte{}, errors.New("password key derivation function returned an invalid key length")
}

func hashFile(fileName string) (string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return "", err
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Use io copy to stream file through the hash algo
	hashComp := sha256.New()
	_, err = io.Copy(hashComp, file)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hashComp.Sum(nil)), nil
}

func encryptBlobAESGCM256(blob *[]byte, key []byte) (*[]byte, error) {
	if blob == nil {
		return nil, errors.New("invalid data supplied")
	}

	if len(key) != 32 {
		return nil, errors.New("invalid key size supplied - this function takes 256 bits of key material")
	}

	/*
		AES is fundamentally a block cipher, but we can use it in GCM mode as a streaming cipher
		which is desirable because we don't want to manipulate our input sizes for crypto reasons,
		nor introduce padding into the output (making our ability to chunk data on large files
		simpler) while keeping very strong protection AND authentication
	*/
	blockAES, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("internal crypto error attempting to create cipher object: %w", err)
	}

	/*
		Nonces are a critical aspect of the AES-GCM combination.  Important considerations include
		ensuring that you never re-use the same nonce with the same key - for a given piece of
		content using a non ephemeral key we can come up with a careful iterative paradigm, or we
		can generate a random nonce if we accept the size of the likely collision space

		The nonce is a 12 byte value (technically you can supply a larger nonce but anything larger
		than 12 bytes will be internally hashed back into 12) meaning we should limit ourselves
		to 2^32 uses of nonce randomization for a given key (the collision space is 2^96)

		For this type of encryption/decryption tool this should be deemed safe
	*/
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("internal crypto error generating random data - possible exhaustion of system entropy: %w", err)
	}

	blockAESGCM, err := cipher.NewGCM(blockAES)
	if err != nil {
		return nil, fmt.Errorf("internal crypto error creating mode block for cipher: %w", err)
	}

	/*
		We don't supply additional authenticated data (AAD) because it has nothing to do with security
		(it's a metadata methodology to tag along with the resulting ciphertext)

		Note: Passing the nonce as the first argument to Seal apparently get Seal to prefix the
		ciphertext with the nonce (which we want) which did not seem to match the documentation
		for that argument
	*/
	encryptedData := blockAESGCM.Seal(nonce, nonce, *blob, nil)

	return &encryptedData, nil
}

func decryptBlobAESGCM256(blob *[]byte, key []byte) (*[]byte, error) {
	if blob == nil {
		return nil, errors.New("invalid data supplied")
	}

	if len(key) != 32 {
		return nil, errors.New("invalid key size supplied - this function takes 256 bits of key material")
	}

	blockAES, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("internal crypto error attempting to create cipher object: %w", err)
	}

	blockAESGCM, err := cipher.NewGCM(blockAES)
	if err != nil {
		return nil, fmt.Errorf("internal crypto error creating mode block for cipher: %w", err)
	}

	// Extract the nonce - which we expect to be prepended to the encrypted data
	nonceSize := blockAESGCM.NonceSize()
	nonce, ciphertext := (*blob)[:nonceSize], (*blob)[nonceSize:]

	plaintext, err := blockAESGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt the data using the provided key material: %w", err)
	}

	return &plaintext, nil
}
