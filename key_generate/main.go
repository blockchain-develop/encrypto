package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("invalid input")
	}
	key := os.Args[1]
	//
	hash := sha256.New()
	hash.Write([]byte(key))
	hashKey := hash.Sum(nil)
	fmt.Printf("%x\n", hashKey)
}
