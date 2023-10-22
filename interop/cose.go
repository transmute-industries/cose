package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type ProtectedHeader map[int]interface{}
type UnprotectedHeader map[int]interface{}
type CoseKey map[int]interface{}
type CoseSign1Signer = func(p ProtectedHeader, u UnprotectedHeader, c []byte) ([]byte, error)
type CoseSign1Verifier = func(s []byte, c []byte) bool

// OS2IP - Octet-String-to-Integer primitive converts an octet string to a
// nonnegative integer.
// OS2IP is used for decoding ECDSA signature (r, s) from byte strings.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
func OS2IP(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}

// I2OSP - Integer-to-Octet-String primitive converts a nonnegative integer to
// an octet string of a specified length `len(buf)`, and stores it in `buf`.
// I2OSP is used for encoding ECDSA signature (r, s) into byte strings.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
func I2OSP(x *big.Int, buf []byte) error {
	if x.Sign() < 0 {
		return errors.New("I2OSP: negative integer")
	}
	if x.BitLen() > len(buf)*8 {
		return errors.New("I2OSP: integer too large")
	}
	x.FillBytes(buf)
	return nil
}

func EncodeCborBytes(a interface{}) ([]byte, error) {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		fmt.Println(err)
	}
	encodedBytes, err := em.Marshal(a)
	if err != nil {
		fmt.Println(err)
	}
	return encodedBytes, err
}

func decodeSecretKey(a []byte) CoseKey {
	var tmp map[any]any
	cbor.Unmarshal(a, tmp)
	coseKey := CoseKey{
		1:  tmp[1],
		2:  tmp[2],
		3:  tmp[3],
		-1: tmp[-1],
		-2: tmp[-2],
		-3: tmp[-3],
		-4: tmp[-4],
	}
	return coseKey
}

func decodePublicKey(a []byte) CoseKey {
	var tmp map[any]any
	cbor.Unmarshal(a, tmp)
	coseKey := CoseKey{
		1:  tmp[1],
		2:  tmp[2],
		3:  tmp[3],
		-1: tmp[-1],
		-2: tmp[-2],
		-3: tmp[-3],
	}
	return coseKey
}

func calculateCoseKeyThumbprint(coseKey CoseKey) ([]byte, error) {
	encodedCoseKey, err := EncodeCborBytes(coseKey)
	h := sha256.New()
	h.Write(encodedCoseKey)
	bs := h.Sum(nil)
	return bs, err
}

func GenerateSecretKey() (CoseKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	coseKey := CoseKey{
		1:  2,
		3:  -7,
		-1: 1,
		-2: privateKey.X.Bytes(),
		-3: privateKey.Y.Bytes(),
		-4: privateKey.D.Bytes(),
	}
	ckt, err := calculateCoseKeyThumbprint(coseKey)
	coseKey[2] = ckt
	return coseKey, err
}

func PublicKey(coseKey CoseKey) CoseKey {
	publicKey := CoseKey{
		1:  coseKey[1],
		2:  coseKey[2],
		3:  coseKey[3],
		-1: coseKey[-1],
		-2: coseKey[-2],
		-3: coseKey[-3],
	}
	return publicKey
}

func CreateSign(coseKey CoseKey) CoseSign1Signer {
	coseSign1SecretKeySigner := func(p ProtectedHeader, u UnprotectedHeader, c []byte) ([]byte, error) {
		privateKey := coseKeyToEcdsaPrivateKey((coseKey))
		m := c            // TODO encode cbor to be signed here.
		h := sha256.New() // this needs to change as alg changes
		h.Write(m)
		digest := h.Sum(nil)
		signature, err := privateKey.Sign(rand.Reader, digest, nil)
		// TODO: unmarshal ASN1 ... fix cose structure...
		return signature, err
	}

	return coseSign1SecretKeySigner
}

func coseKeyToEcdsaPublicKey(coseKey CoseKey) *ecdsa.PublicKey {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// there has to be a better way to get an empty instance of type
	// if only I knew how to program in go...
	x, _ := coseKey[-2].([]byte)
	y, _ := coseKey[-3].([]byte)
	privateKey.X.SetBytes(x)
	privateKey.Y.SetBytes(y)
	var ecdsaKey *ecdsa.PublicKey
	ecdsaKey = privateKey.Public().(*ecdsa.PublicKey)
	return ecdsaKey
}

func coseKeyToEcdsaPrivateKey(coseKey CoseKey) *ecdsa.PrivateKey {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// there has to be a better way to get an empty instance of type
	// if only I knew how to program in go...
	x, _ := coseKey[-2].([]byte)
	y, _ := coseKey[-3].([]byte)
	d, _ := coseKey[-4].([]byte)
	privateKey.X.SetBytes(x)
	privateKey.Y.SetBytes(y)
	privateKey.D.SetBytes(d)
	return privateKey
}

func CreateVerify(coseKey CoseKey) CoseSign1Verifier {
	coseSign1PublicKeyVerifier := func(sigASN1 []byte, c []byte) bool {
		publicKey := coseKeyToEcdsaPublicKey(coseKey)
		m := c            // TODO encode cbor to be signed here.
		h := sha256.New() // this needs to change as alg changes
		h.Write(m)
		digest := h.Sum(nil)
		var unmarshaledASN1Signature struct {
			R, S *big.Int
		}
		// when your standard library forces you to use an ASN.1 parser...
		if _, err := asn1.Unmarshal(sigASN1, &unmarshaledASN1Signature); err != nil {
			return false
		}

		v := ecdsa.Verify(publicKey, digest, unmarshaledASN1Signature.R, unmarshaledASN1Signature.S)
		return v
	}

	return coseSign1PublicKeyVerifier
}
