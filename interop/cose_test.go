package cose

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// func TestSignAndVerify(t *testing.T) {

// 	// secretKey, _ := GenerateSecretKey(-7)
// 	// publicKey := PublicKey(secretKey)
// 	// encodedSecretKey, _ := EncodeCborBytes(secretKey)
// 	// encodedPublicKey, _ := EncodeCborBytes(publicKey)
// 	// diagnosticOfPublicKey, _ := cbor.Diagnose(encodedPublicKey)
// 	// diagnosticOfSecretKey, _ := cbor.Diagnose(encodedSecretKey)

// 	// f2, err := os.Create("publicKey.cose")
// 	// check(err)
// 	// defer f2.Close()
// 	// f2.Write(encodedPublicKey)

// 	// f1, err := os.Create("secretKey.cose")
// 	// check(err)
// 	// defer f1.Close()
// 	// f1.Write(encodedSecretKey)

// 	cborEncodedSecretKey, _ := ioutil.ReadFile("secretKey.cose")
// 	secretKey := decodeSecretKey(cborEncodedSecretKey)

// 	cborEncodedPublicKey, _ := ioutil.ReadFile("publicKey.cose")
// 	publicKey := decodePublicKey(cborEncodedPublicKey)

// 	sign := CreateSign(secretKey)
// 	verify := CreateVerify(publicKey)

// 	p := ProtectedHeader{1: -7}
// 	u := UnprotectedHeader{}
// 	c := []byte("fake")

// 	s, _ := sign(p, u, c)

// 	f1, err := os.Create("sign1.cose")
// 	check(err)
// 	defer f1.Close()
// 	f1.Write(s)

// 	// s must be made a cose sign 1
// 	v := verify(s)

// 	if !v {
// 		t.Errorf("verification %t", v)
// 	}
// }

func TestDilithium(t *testing.T) {
	message := []byte("fake")
	mode := dilithium.ModeByName("Dilithium2")
	publicKey, privateKey, _ := mode.GenerateKey(rand.Reader)
	signature := mode.Sign(privateKey, message)
	verified := mode.Verify(publicKey, message, signature)
	if !verified {
		t.Errorf("verification %t", verified)
	}
}

func TestCoseDilithium(t *testing.T) {
	// what should dilithium 2 be ?
	dilithium2CoseAlg := -55555
	secretKey, _ := GenerateSecretKey(dilithium2CoseAlg)
	publicKey := PublicKey(secretKey)
	encodedSecretKey, _ := EncodeCborBytes(secretKey)
	encodedPublicKey, _ := EncodeCborBytes(publicKey)

	f1, _ := os.Create("dilithium.secretKey.cose")
	defer f1.Close()
	f1.Write(encodedSecretKey)

	f2, _ := os.Create("dilithium.publicKey.cose")
	defer f2.Close()
	f2.Write(encodedPublicKey)

	sign := CreateSign(secretKey)
	p := ProtectedHeader{1: publicKey[3]}
	u := UnprotectedHeader{}
	c := []byte("fake")
	s, _ := sign(p, u, c)

	f3, _ := os.Create("dilithium.sign1.cose")
	defer f3.Close()
	f3.Write(s)

	verify := CreateVerify(publicKey)

	v := verify(s)

	if !v {
		t.Errorf("verification %t", v)
	}

}
