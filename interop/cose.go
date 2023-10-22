package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/fxamacker/cbor/v2"
)

type ProtectedHeader map[int]interface{}
type UnprotectedHeader map[int]interface{}
type CoseKey map[int]interface{}
type CoseSign1Signer = func(p ProtectedHeader, u UnprotectedHeader, c []byte) ([]byte, error)
type CoseSign1Verifier = func(s []byte) bool

type signedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected UnprotectedHeader
	Payload     []byte
	Signature   []byte
}

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

// encodeECDSASignature encodes (r, s) into a signature binary string using the
// method specified by RFC 8152 section 8.1.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
func encodeECDSASignature(curve elliptic.Curve, r, s *big.Int) ([]byte, error) {
	n := (curve.Params().N.BitLen() + 7) / 8
	sig := make([]byte, n*2)
	if err := I2OSP(r, sig[:n]); err != nil {
		return nil, err
	}
	if err := I2OSP(s, sig[n:]); err != nil {
		return nil, err
	}
	return sig, nil
}

// decodeECDSASignature decodes (r, s) from a signature binary string using the
// method specified by RFC 8152 section 8.1.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
func decodeECDSASignature(curve elliptic.Curve, sig []byte) (r, s *big.Int, err error) {
	n := (curve.Params().N.BitLen() + 7) / 8
	if len(sig) != n*2 {
		return nil, nil, fmt.Errorf("invalid signature length: %d", len(sig))
	}
	return OS2IP(sig[:n]), OS2IP(sig[n:]), nil
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
	var secretKey CoseKey
	cbor.Unmarshal(a, &secretKey)
	return secretKey
}

func decodePublicKey(a []byte) CoseKey {
	var publicKey CoseKey
	cbor.Unmarshal(a, &publicKey)
	return publicKey
}

func calculateCoseKeyThumbprint(coseKey CoseKey) ([]byte, error) {
	encodedCoseKey, err := EncodeCborBytes(coseKey)
	h := sha256.New()
	h.Write(encodedCoseKey)
	bs := h.Sum(nil)
	return bs, err
}

func generatePrivateKeyForAlg(alg int) (*ecdsa.PrivateKey, error) {
	switch alg {
	case -7:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return privateKey, err
	case -35:
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return privateKey, err
	case -36:
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return privateKey, err
	default:
		return nil, errors.New("Algorithm not supported")
	}

}

func GenerateSecretKey(alg int) (CoseKey, error) {
	var coseKey CoseKey
	if alg == -55555 {
		mode := dilithium.ModeByName("Dilithium2")
		publicKey, privateKey, _ := mode.GenerateKey(rand.Reader)
		coseKey = CoseKey{
			1:   7,
			3:   alg,
			-13: privateKey.Bytes(),
			-14: publicKey.Bytes(),
		}
	} else {
		privateKey, err := generatePrivateKeyForAlg(alg)
		if err != nil {
			fmt.Println(err)
		}
		coseKey = CoseKey{
			1:  2,
			3:  alg,
			-1: 1,
			-2: privateKey.X.Bytes(),
			-3: privateKey.Y.Bytes(),
			-4: privateKey.D.Bytes(),
		}

	}
	ckt, err := calculateCoseKeyThumbprint(coseKey)
	coseKey[2] = ckt
	return coseKey, err

}

func PublicKey(coseKey CoseKey) CoseKey {
	publicKey := CoseKey{
		1: coseKey[1],
		2: coseKey[2],
		3: coseKey[3],
	}
	if coseKey[1] == 7 { // kty PQC
		publicKey[-14] = coseKey[-14]
	} else { // kty EC2
		publicKey[-1] = coseKey[-1]
		publicKey[-2] = coseKey[-2]
		publicKey[-3] = coseKey[-3]
	}
	return publicKey
}

func coseKeyToEcdsaPublicKey(coseKey CoseKey) *ecdsa.PublicKey {
	var pubkey ecdsa.PublicKey
	pubkey.Curve = elliptic.P256()
	switch alg := coseKey[3]; alg {
	case -7:
		break
	case -35:
		pubkey.Curve = elliptic.P384()
		break
	case -36:
		pubkey.Curve = elliptic.P521()
		break
	}
	pubkey.X = big.NewInt(0).SetBytes(coseKey[-2].([]byte))
	pubkey.Y = big.NewInt(0).SetBytes(coseKey[-3].([]byte))
	return &pubkey
}

func coseKeyToEcdsaPrivateKey(coseKey CoseKey) *ecdsa.PrivateKey {
	var secretKey ecdsa.PrivateKey
	secretKey.Curve = elliptic.P256()
	switch alg := coseKey[3]; alg {
	case -7:
		break
	case -35:
		secretKey.Curve = elliptic.P384()
		break
	case -36:
		secretKey.Curve = elliptic.P521()
		break
	}
	secretKey.X = big.NewInt(0).SetBytes(coseKey[-2].([]byte))
	secretKey.Y = big.NewInt(0).SetBytes(coseKey[-3].([]byte))
	secretKey.D = big.NewInt(0).SetBytes(coseKey[-4].([]byte))
	return &secretKey
}

func digestForCoseKey(content []byte, coseKey CoseKey) ([]byte, error) {
	switch alg := coseKey[3]; alg {
	case -7:
		h := sha256.New()
		h.Write(content)
		digest := h.Sum(nil)
		return digest, nil
	case -35:
		h := sha512.New384()
		h.Write(content)
		digest := h.Sum(nil)
		return digest, nil
	case -36:
		h := sha512.New()
		h.Write(content)
		digest := h.Sum(nil)
		return digest, nil
	default:
		return nil, errors.New("COSE Key does not restrict algorithm")
	}
}

func getToBeSignedDigest(coseKey CoseKey, p ProtectedHeader, u UnprotectedHeader, c []byte) ([]byte, []byte, []byte, error) {
	em, _ := cbor.CanonicalEncOptions().EncMode()
	// make protected header
	var protectedHeaderBytes []byte
	if len(p) >= 0 {
		protectedHeaderBytes, _ = em.Marshal(p)
	}
	// make eadd
	var externalAAD []byte
	var tbsArray = []interface{}{"Signature1", protectedHeaderBytes, externalAAD, c}
	var tbsBytes, _ = cbor.Marshal(tbsArray)
	tbsDigest, err := digestForCoseKey(tbsBytes, coseKey)
	return tbsDigest, tbsBytes, protectedHeaderBytes, err
}

func encodeCoseSign1(protectedHeaderBytes []byte, u UnprotectedHeader, c []byte, encodedSignature []byte) ([]byte, error) {
	var coseSign1 = signedCWT{
		Protected:   protectedHeaderBytes,
		Unprotected: u,
		Payload:     c,
		Signature:   encodedSignature,
	}
	tags := cbor.NewTagSet()
	tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(signedCWT{}),
		18)
	em2, _ := cbor.EncOptions{}.EncModeWithTags(tags)
	taggedCoseSign1, err := em2.Marshal(coseSign1)
	return taggedCoseSign1, err
}

func removeShamefulDependencyOnASN1Parser(privateKey *ecdsa.PrivateKey, marshaledASN1Signature []byte) ([]byte, error) {
	var unmarshaledASN1Signature struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(marshaledASN1Signature, &unmarshaledASN1Signature); err != nil {
		return nil, err
	}
	encodedSignature, err := encodeECDSASignature(privateKey.Curve, unmarshaledASN1Signature.R, unmarshaledASN1Signature.S)
	return encodedSignature, err
}

func CreateSign(coseKey CoseKey) CoseSign1Signer {
	coseSign1SecretKeySigner := func(p ProtectedHeader, u UnprotectedHeader, c []byte) ([]byte, error) {
		tbsDigest, tbs, protectedHeaderBytes, _ := getToBeSignedDigest(coseKey, p, u, c)

		var encodedSignature []byte
		// this part changes with alg
		if coseKey[1] == 7 {
			mode := dilithium.ModeByName("Dilithium2")

			secretKey := mode.PrivateKeyFromBytes(coseKey[-13].([]byte))
			encodedSignature = mode.Sign(secretKey, tbs)
		} else {

			privateKey := coseKeyToEcdsaPrivateKey(coseKey)
			marshaledASN1Signature, _ := privateKey.Sign(rand.Reader, tbsDigest, nil)
			encodedSignature, _ = removeShamefulDependencyOnASN1Parser(privateKey, marshaledASN1Signature)
		}
		// this part changes with alg

		return encodeCoseSign1(protectedHeaderBytes, u, c, encodedSignature)
	}
	return coseSign1SecretKeySigner
}

func recoverTbsDigest(coseKey CoseKey, coseSign1 []byte) ([]byte, []byte, []byte, error) {
	tags := cbor.NewTagSet()
	tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(signedCWT{}),
		18)
	dm, _ := cbor.DecOptions{}.DecModeWithTags(tags)
	var decodedCoseSign1 signedCWT
	dm.Unmarshal(coseSign1, &decodedCoseSign1)
	var externalAAD []byte
	var tbsArray = []interface{}{"Signature1", decodedCoseSign1.Protected, externalAAD, decodedCoseSign1.Payload}
	var tbsBytes, _ = cbor.Marshal(tbsArray)
	tbsDigest, err := digestForCoseKey(tbsBytes, coseKey)
	return tbsDigest, tbsBytes, decodedCoseSign1.Signature, err
}

func CreateVerify(coseKey CoseKey) CoseSign1Verifier {
	coseSign1PublicKeyVerifier := func(coseSign1 []byte) bool {
		digest, tbs, signature, _ := recoverTbsDigest(coseKey, coseSign1)
		// this part changes with alg
		if coseKey[1] == 7 {
			mode := dilithium.ModeByName("Dilithium2")
			publicKey := mode.PublicKeyFromBytes(coseKey[-14].([]byte))
			verification := mode.Verify(publicKey, tbs, signature)
			return verification
		} else {
			publicKey := coseKeyToEcdsaPublicKey(coseKey)
			r, s, _ := decodeECDSASignature(publicKey.Curve, signature)
			verification := ecdsa.Verify(publicKey, digest, r, s)
			return verification
		}
		// this part changes with alg

	}
	return coseSign1PublicKeyVerifier
}
