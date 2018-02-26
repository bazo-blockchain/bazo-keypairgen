package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: bazo-rootgen <filename>")
	}

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	//Write the public key to the given textfile
	if _, err = os.Stat(os.Args[1]); !os.IsNotExist(err) {
		log.Fatal("Output file exists.")
	}

	file, err := os.Create(os.Args[1])
	if err != nil {
		log.Fatal("Cannot create file.")
	}

	var pubKey [64]byte

	_, err1 := file.WriteString(string(newKey.X.Text(16)) + "\n")
	_, err2 := file.WriteString(string(newKey.Y.Text(16)) + "\n")
	_, err3 := file.WriteString(string(newKey.D.Text(16)) + "\n")

	newAccPub1, newAccPub2 := newKey.PublicKey.X.Bytes(), newKey.PublicKey.Y.Bytes()
	copy(pubKey[0:32], newAccPub1)
	copy(pubKey[32:64], newAccPub2)

	fmt.Printf("PublicKey Hash: %x\n", serializeHashContent(pubKey[:]))

	if err1 != nil || err2 != nil || err3 != nil {
		log.Fatal("Failed to write key to file.")
	}
}

func serializeHashContent(data interface{}) (hash [32]byte) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, data)
	return sha3.Sum256(buf.Bytes())
}
