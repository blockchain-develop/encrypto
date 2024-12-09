package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		panic("invalid input")
	}
	op := os.Args[1]
	inputFile := os.Args[2]
	key := os.Args[3]
	//
	hash := sha256.New()
	hash.Write([]byte(key))
	hashKey := hash.Sum(nil)
	//
	input, err := os.ReadFile(inputFile)
	if err != nil {
		panic(err)
	}
	switch op {
	case "e":
		output := encrypt(string(input), hashKey)
		os.WriteFile(fmt.Sprintf("%s_e", inputFile), []byte(output), 0644)
	case "d":
		output := decrypt(string(input), hashKey)
		os.WriteFile(fmt.Sprintf("%s_d", inputFile), []byte(output), 0644)
	default:
		panic("invalid input")
	}
}

func encrypt(stringToEncrypt string, key []byte) (encryptedString string) {
	//Since the key is in string, we need to convert decode it to bytes
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, key []byte) (decryptedString string) {
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
