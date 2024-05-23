package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	AES128_KEY_SIZE = 16 //128 bits
	AESGCM_IV_SIZE  = 12 //96 bits

	ARGON2ID_SALT_SIZE = 16 //128 bits
	ARGON2ID_PARA      = 1
	ARGON2ID_ITERATION = 2
	ARGON2ID_MEM       = 19 * 1024 //19MB
)

func PwdToKey(pwd string) ([]byte, []byte, error) {
	salt := make([]byte, ARGON2ID_SALT_SIZE)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	return salt, argon2.IDKey([]byte(pwd), salt, ARGON2ID_ITERATION,
			ARGON2ID_MEM, ARGON2ID_PARA, AES128_KEY_SIZE),
		nil
}

func Aes128GcmEnc(key, pt, ad []byte) ([]byte, []byte, error) {
	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(bc)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv := make([]byte, AESGCM_IV_SIZE)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	return iv, aesgcm.Seal(nil, iv, pt, ad), nil
}

func Aes128GcmDec(key, iv, ct, ad []byte) ([]byte, error) {
	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(bc)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, iv, ct, ad)
}

func main() {

	//password based encryption
	pwd := "example password"
	fmt.Println("password: ", pwd)

	pt := "example plain text"
	fmt.Println("plain text: ", pt)

	ad := "example additional data"
	fmt.Println("additional data: ", ad)

	salt, key, _ := PwdToKey(pwd)
	fmt.Println("salt: ", salt)
	fmt.Println("key: ", key)

	iv, ct, _ := Aes128GcmEnc(key, []byte(pt), []byte(ad))
	fmt.Println("iv: ", iv)
	fmt.Println("cipher text: ", ct)

	decPt, _ := Aes128GcmDec(key, iv, ct, []byte(ad))
	fmt.Println("decrypted plain text: ", string(decPt))

}
