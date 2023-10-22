package cose

import (
	"crypto/rand"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
)

func TestDilithiumJose(t *testing.T) {

	mode := dilithium.ModeByName("Dilithium2")
	publicKey, privateKey, _ := mode.GenerateKey(rand.Reader)

	privateKeyMap := map[string]string{
		"kty":  "MLWE",
		"alg":  "CRYDI2",
		"pub":  b64.RawURLEncoding.EncodeToString(publicKey.Bytes()),
		"priv": b64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
	}

	publicKeyMap := map[string]string{
		"kty": "MLWE",
		"alg": "CRYDI2",
		"pub": b64.RawURLEncoding.EncodeToString(publicKey.Bytes()),
	}

	privateKeyJwk, _ := json.MarshalIndent(privateKeyMap, "", "  ")
	os.WriteFile("dilithium.secretKey.jwk.json", privateKeyJwk, 0644)

	publicKeyJwk, _ := json.MarshalIndent(publicKeyMap, "", "  ")
	os.WriteFile("dilithium.publicKey.jwk.json", publicKeyJwk, 0644)
	protectedHeaderMap := map[string]string{
		"alg": "CRYDI2",
		"kid": "42",
	}
	payloadMap := map[string]string{
		"iss": "urn:uuid:123",
		"sub": "urn:uuid:456",
	}
	headerString, _ := json.Marshal(protectedHeaderMap)
	payloadString, _ := json.Marshal(payloadMap)
	tbs := string(b64.RawURLEncoding.EncodeToString([]byte(headerString))) + "." + string(b64.RawURLEncoding.EncodeToString([]byte(payloadString)))
	signature := mode.Sign(privateKey, []byte(tbs))
	jws := tbs + "." + string(b64.RawURLEncoding.EncodeToString(signature))
	os.WriteFile("dilithium.jws.jose", []byte(jws), 0644)
	s := strings.Split(jws, ".")[2]
	decodedSignature, _ := base64.RawURLEncoding.DecodeString(s)
	verified := mode.Verify(publicKey, []byte(tbs), decodedSignature)
	if !verified {
		t.Errorf("verification %t", verified)
	}
}
