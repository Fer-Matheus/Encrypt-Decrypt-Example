package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

func main() {

	// Establishing a connection with the TPM
	tpm, err := tpm2.OpenTPM()
	if err != nil {
		fmt.Println("Error open TPM: ", err)
		return
	}

	// Define a rsa key template to use in CreatePrimary method
	keyTemplate := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagDecrypt | tpm2.FlagUserWithAuth,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  nil,
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	// Creating a key using the template defined above, bellow the Owner hieric
	keyHandle, outPublic, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", keyTemplate)
	if err != nil {
		fmt.Println("Error creating key: ", err)
		return
	}

	data := []byte("Matheus Freitas esteve aqui!")
	dataSize := len(data)
	rsaPub := outPublic.(*rsa.PublicKey)

	encData, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, data)
	if err != nil {
		fmt.Println("Error encrypting data: ", err)
		return
	}
	fmt.Println("\nData (string): ", string(data))
	fmt.Println("\nData (hex): ", data)
	fmt.Println("\nEncrypted Data : ", encData)

	decData, err := tpm2.RSADecrypt(tpm, keyHandle, "", encData, &tpm2.AsymScheme{}, "")
	if err != nil {
		fmt.Println("Error decrypting data: ", err)
		return
	}

	fmt.Println("\nDecrypted Data : ", decData)

	fmt.Println("\nDecrypetd: ", decData[len(decData)-dataSize:])
	fmt.Println("\nstring format (data): ", string(decData[len(decData)-dataSize:]))

}
