package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls/common"
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

	//ECDSA secp256k1 bitcoin/eth signature
	fmt.Println("ECDSA secp256k1 signature: ")
	ecdsaMsg := "example ecdsa message"
	fmt.Println("msg: ", ecdsaMsg)
	hash := sha3.Sum256([]byte(ecdsaMsg))
	fmt.Println("msg hash: ", hash)
	ecdsaKey, _ := gethcrypto.GenerateKey()
	fmt.Println("ecdsa keypair: ", ecdsaKey)
	sig, _ := gethcrypto.Sign(hash[:], ecdsaKey)
	fmt.Println("msg sig: ", sig)
	s256PubKey, err := gethcrypto.SigToPub(hash[:], sig)
	if err != nil {
		fmt.Println("ecrecover error: ", err)
	}
	valid := s256PubKey.Equal(&ecdsaKey.PublicKey)
	fmt.Println("ecdsa verify: ", valid)
	fmt.Println()

	//store ECDSA secp256k1 key in geth legacy encrypted(insecure) pem format
	fmt.Println("ECDSA secp256k1 key stored to geth legacy encrypted pem format: ")
	keyData := gethcrypto.FromECDSA(ecdsaKey)
	block, _ := x509.EncryptPEMBlock(rand.Reader, "secp256k1 PRIVATE KEY",
		keyData, []byte(pwd), x509.PEMCipherAES128)
	pemData := pem.EncodeToMemory(block)
	fmt.Println("ECDSA secp256k1 private key in geth legacy encrypted pem format: ", string(pemData))
	block, _ = pem.Decode(pemData)
	s256KeyData, err := x509.DecryptPEMBlock(block, []byte(pwd))
	if err != nil {
		fmt.Println("pem dec: ", err)
	}
	s256Key, err := gethcrypto.ToECDSA(s256KeyData)
	if err != nil {
		fmt.Println("parse pkcs8: ", err)
	}
	fmt.Println("ECDSA secp256k1 decoded key == original key: ", ecdsaKey.Equal(s256Key))
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
	fmt.Println()

	//store ed25519 key in pkcs8+pem format
	//(unencrypted because Legacy PEM encryption is NOT secure and pkcs5 not implemented in golang)
	fmt.Println("ED25519 key stored to pkcs8 pem format: ")
	edKeyData, _ := x509.MarshalPKCS8PrivateKey(priKey)
	pemData = pem.EncodeToMemory(
		&pem.Block{
			Type:  "ED25519 PRIVATE KEY",
			Bytes: edKeyData,
		},
	)
	fmt.Println("ED25519 private key in pkcs8 pem format: ", string(pemData))
	block, _ = pem.Decode(pemData)
	decodedPriKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	edPriKey := decodedPriKey.(ed25519.PrivateKey)
	fmt.Println("ED25519 decoded key == original key: ", priKey.Equal(edPriKey))
	fmt.Println()

	//store ed25519 key in encrypted openssh pem format
	fmt.Println("ED25519 key stored to encrypted openssh pem format: ")
	block, _ = ssh.MarshalPrivateKeyWithPassphrase(priKey, "ed25519", []byte(pwd))
	pemStr := pem.EncodeToMemory(block)
	fmt.Println("ED25519 private key in encrypted openssh pem format: ", string(pemStr))
	//block, _ = pem.Decode(pemStr)
	tmpKeyData, _ := ssh.ParseRawPrivateKeyWithPassphrase(pemStr, []byte(pwd))
	edPriKeyP := tmpKeyData.(*ed25519.PrivateKey)
	fmt.Println("ED25519 decoded key == original key: ", priKey.Equal(*edPriKeyP))
	fmt.Println()

	//bls signature
	fmt.Println("bls signature: ")
	blsMsg := "example bls message"
	fmt.Println("bls msg: ", blsMsg)
	blsMsgHash := sha3.Sum256([]byte(blsMsg))
	fmt.Println("bls msg hash: ", blsMsgHash)
	blsSigs := make([]common.Signature, 3)
	blsKeys := make([]common.SecretKey, 3)
	blsPubKeys := make([]common.PublicKey, 3)
	blsKeys[0], _ = bls.RandKey()
	blsPubKeys[0] = blsKeys[0].PublicKey()
	blsSigs[0] = blsKeys[0].Sign(blsMsgHash[:])
	blsKeys[1], _ = bls.RandKey()
	blsPubKeys[1] = blsKeys[1].PublicKey()
	blsSigs[1] = blsKeys[1].Sign(blsMsgHash[:])
	blsKeys[2], _ = bls.RandKey()
	blsPubKeys[2] = blsKeys[2].PublicKey()
	blsSigs[2] = blsKeys[2].Sign(blsMsgHash[:])
	for i := 0; i < 3; i++ {
		fmt.Println("--------------------------")
		fmt.Println("bls keys: ", i, blsKeys[i].Marshal())
		fmt.Println("bls pub keys: ", i, blsPubKeys[i].Marshal())
		fmt.Println("bls signatures: ", i, blsSigs[i].Marshal())
		fmt.Println("--------------------------")
	}
	//aggregate signatures
	blsAggSig := bls.AggregateSignatures(blsSigs)
	fmt.Println("bls aggregated signature: ", blsAggSig.Marshal())
	//aggregate public keys
	blsAggPubKey := bls.AggregateMultiplePubkeys(blsPubKeys)
	fmt.Println("bls aggregated pubkey: ", blsAggPubKey.Marshal())
	//verify agg sigs
	verify := blsAggSig.Verify(blsAggPubKey, blsMsgHash[:])
	fmt.Println("bls signature verify: ", verify)
	verifyMultiple := blsAggSig.FastAggregateVerify(blsPubKeys, blsMsgHash)
	fmt.Println("bls signature verify multiple: ", verifyMultiple)
}
