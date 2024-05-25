package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
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

func Aes128CtrEnc(key, pt []byte) ([]byte, []byte, error) {
	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, bc.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	aesctr := cipher.NewCTR(bc, iv)

	reader := bytes.NewReader(pt)
	var out bytes.Buffer
	writer := &cipher.StreamWriter{S: aesctr, W: &out}
	//stream encryption
	if _, err := io.Copy(writer, reader); err != nil {
		return nil, nil, err
	}

	return iv, out.Bytes(), nil
}

func Aes128CtrDec(key, iv, ct []byte) ([]byte, error) {
	bc, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesctr := cipher.NewCTR(bc, iv)

	reader := bytes.NewReader(ct)
	var out bytes.Buffer
	writer := &cipher.StreamWriter{S: aesctr, W: &out}
	//stream encryption
	if _, err := io.Copy(writer, reader); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func GenHmacSha3(iv, msg, key []byte) []byte {
	mac := hmac.New(sha3.New256, key)
	//stream write
	mac.Write(iv)
	mac.Write(msg)
	return mac.Sum(nil)
}

func VerifyHmacSha3(iv, msg, msgMac, key []byte) bool {
	mac := hmac.New(sha3.New256, key)
	//stream write
	mac.Write(iv)
	mac.Write(msg)
	expectedMac := mac.Sum(nil)
	return hmac.Equal(msgMac, expectedMac)
}

func main() {

	//password based encryption:
	//argon2id + aes-gcm
	fmt.Println("password based encryption: argon2id + aes-gcm")
	pwd := "example password"
	fmt.Println("password: ", pwd)

	pt := "example key data"
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

	fmt.Println()

	//stream cipher + mac:
	//aes-ctr + hmac
	fmt.Println("stream cipher + mac: aes-ctr + hmac")
	plainText := "example plain text"
	fmt.Println("plain text: ", plainText)
	iv, cipherText, _ := Aes128CtrEnc(key, []byte(plainText))
	fmt.Println("iv: ", iv)
	fmt.Println("cipher text: ", cipherText)
	msgMac := GenHmacSha3(iv, cipherText, key)
	fmt.Println("hmac-sha3: ", msgMac)
	success := VerifyHmacSha3(iv, cipherText, msgMac, key)
	fmt.Println("hmac-sha3 verify: ", success)
	decPt, _ = Aes128CtrDec(key, iv, cipherText)
	fmt.Println("decrypted plain text: ", string(decPt))

	fmt.Println()
	//RSA encryption
	fmt.Println("RSA-OAEP encryption: ")
	rsaMsg := "example rsa message"
	fmt.Println("rsa plain text: ", rsaMsg)
	rsaLbl := "example rsa label"
	fmt.Println("rsa label: ", rsaLbl)
	rsaKeyPair, _ := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Println("rsa key pair: ", rsaKeyPair)
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKeyPair.PublicKey, []byte(rsaMsg), []byte(rsaLbl))
	fmt.Println("rsa encrypted message: ", ciphertext)
	decRsaPt, _ := rsa.DecryptOAEP(sha256.New(), nil, rsaKeyPair, ciphertext, []byte(rsaLbl))
	fmt.Println("rsa decrypted text: ", string(decRsaPt))

	fmt.Println()
	//ECDSA signature
	fmt.Println("ECDSA signature: ")
	ecdsaMsg := "example ecdsa message"
	fmt.Println("msg: ", ecdsaMsg)
	hash := sha3.Sum256([]byte(ecdsaMsg))
	fmt.Println("msg hash: ", hash)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fmt.Println("ecdsa keypair: ", ecdsaKey)
	sig, _ := ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
	fmt.Println("msg sig: ", sig)
	valid := ecdsa.VerifyASN1(&ecdsaKey.PublicKey, hash[:], sig)
	fmt.Println("ecdsa verify: ", valid)

	fmt.Println()
	//ED25519 signature
	fmt.Println("ED25519 signature: ")
	edMsg := "example ed25519 message"
	fmt.Println("msg: ", ecdsaMsg)
	hash = sha3.Sum256([]byte(edMsg))
	fmt.Println("msg hash: ", hash)
	pubKey, priKey, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Println("ed25519 pubkey: ", pubKey)
	fmt.Println("ed25519 prikey: ", priKey)
	sig = ed25519.Sign(priKey, hash[:])
	fmt.Println("msg sig: ", sig)
	valid = ed25519.Verify(pubKey, hash[:], sig)
	fmt.Println("ed25519 verify: ", valid)
}
