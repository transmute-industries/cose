package cose

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func TestGenerateSecretKey(t *testing.T) {
	secretKey, _ := GenerateSecretKey()
	publicKey := PublicKey(secretKey)
	encodedSecretKey, _ := EncodeCborBytes(secretKey)
	encodedPublicKey, _ := EncodeCborBytes(publicKey)
	diagnosticOfPublicKey, _ := cbor.Diagnose(encodedPublicKey)
	diagnosticOfSecretKey, _ := cbor.Diagnose(encodedSecretKey)
	if !strings.Contains(diagnosticOfSecretKey, "1: 2") {
		fmt.Println(diagnosticOfSecretKey)
		t.Errorf("expected diagnostic to contain key type %q", diagnosticOfSecretKey)
		f2, err := os.Create("publicKey.cose")
		check(err)
		defer f2.Close()
		f2.Write(encodedPublicKey)
	}
	if !strings.Contains(diagnosticOfPublicKey, "1: 2") {
		fmt.Println(diagnosticOfPublicKey)
		t.Errorf("expected diagnostic to contain key type %q", diagnosticOfPublicKey)
		f1, err := os.Create("secretKey.cose")
		check(err)
		defer f1.Close()
		f1.Write(encodedSecretKey)
	}
}

func TestSigner(t *testing.T) {
	cborEncodedSecretKey, _ := ioutil.ReadFile("secretKey.cose")
	secretKey := decodeSecretKey(cborEncodedSecretKey)

	cborEncodedPublicKey, _ := ioutil.ReadFile("publicKey.cose")
	// fmt.Println("cborEncodedPublicKey", cborEncodedPublicKey)
	publicKey := decodePublicKey(cborEncodedPublicKey)

	sign := CreateSign(secretKey)
	verify := CreateVerify(publicKey)

	p := ProtectedHeader{1: -7}
	u := UnprotectedHeader{}
	c := []byte("fake")

	s, _ := sign(p, u, c)

	f1, err := os.Create("sign1.cose")
	check(err)
	defer f1.Close()
	f1.Write(s)

	// s must be made a cose sign 1
	v := verify(s)

	if !v {
		t.Errorf("verification %t", v)
	}
}
