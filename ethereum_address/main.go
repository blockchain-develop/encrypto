package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		panic("invalid input")
	}
	mnemonic := os.Args[1]
	password := os.Args[2]
	//
	seed := bip39.NewSeed(mnemonic, password)
	masterPrivateKey, _ := bip32.NewMasterKey(seed)
	//
	purposeKey, err := masterPrivateKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		panic(err)
	}
	coinTypeKey, err := purposeKey.NewChildKey(bip32.FirstHardenedChild + 60)
	if err != nil {
		panic(err)
	}
	accountKey, err := coinTypeKey.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		panic(err)
	}
	changeKey, err := accountKey.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 10; i++ {
		addressKey, err := changeKey.NewChildKey(uint32(i))
		if err != nil {
			panic(err)
		}
		//
		ecdsaPrivateKey := crypto.ToECDSAUnsafe(addressKey.Key)
		ecdsaPublicKey := ecdsaPrivateKey.Public().(*ecdsa.PublicKey)
		//
		address := crypto.PubkeyToAddress(*ecdsaPublicKey)
		fmt.Printf("address %d：%s\n", i, address.Hex())
	}
}
