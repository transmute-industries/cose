# JOSE

Inspired by https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1

~~~~ text
{
  "protected":"<integrity-protected shared header contents>",
  "unprotected":<non-integrity-protected shared header contents>,
  "recipients":[
   {"header":<per-recipient unprotected header 1 contents>,
    "encrypted_key":"<encrypted key 1 contents>"},
   ...
   {"header":<per-recipient unprotected header N contents>,
    "encrypted_key":"<encrypted key N contents>"}],
  "aad":"<additional authenticated data contents>",
  "iv":"<initialization vector contents>",
  "ciphertext":"<ciphertext contents>",
  "tag":"<authentication tag contents>"
}
~~~~

## Public Key

~~~~ json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "kid": "test-key-42",
  "x": "yrDfRkTsnZmIwFl3T-gJxaNfORIhJvtw2XGWzElGf9A",
  "y": "pBpD0OG36Gxv0ikwrl0Q7PPd6ogMqGW6R-C2PW1nelM",
  "use": "enc",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## Private Key

~~~~ json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "kid": "test-key-42",
  "x": "yrDfRkTsnZmIwFl3T-gJxaNfORIhJvtw2XGWzElGf9A",
  "y": "pBpD0OG36Gxv0ikwrl0Q7PPd6ogMqGW6R-C2PW1nelM",
  "d": "t4C7Eimc3xNhM1ii9EoPxyAcQILWoOh0rKnBO8d9mCQ",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQlBqb1RxZFpJanl5QXVNYnlQRGlTZ0Z4Y3RWU210bFZhWkdjZjU0YWFHUndUaHE3WkxPZEZxUWJZRGNvc3BCMjhXZGIxWTVBOXhrUFFET04yYVdUTGxZIiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "qIhjhW7R8n3-NB-ME-VwOLlpAf8qd_HwFrcP"
}
~~~~

## HPKE Usage in Key Agreement with Key Wrapping mode

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.2

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIn0",
  "unprotected": {
    "recipients": [
      {
        "kid": "test-key-42",
        "enc": "BPhp9cyIscc6CGtbwICW9qMRLbjcwdkfAKLy_1QR6KiLqbif2yJNLHks0OV9A0ojE-vpS9CXRikrdqYosJVcOP0",
        "encrypted_key": "tXOaGLXvsCyt8deYPeVu30S1ZDcLrEJzGXNU9nmsY5k"
      }
    ]
  },
  "iv": "mNwSHPo5D1uIp2W1",
  "ciphertext": "5HWIfXNkxnOKXsIulmHbjxExRabwjGJXZoL2"
}
~~~~

# COSE

Inspired by https://datatracker.ietf.org/doc/html/rfc9052#name-encryption-objects

~~~~ text

COSE_Encrypt = [
  Headers,
  ciphertext : bstr / nil,
  recipients : [+COSE_recipient]
]

COSE_recipient = [
  Headers,
  ciphertext : bstr / nil,
  ? recipients : [+COSE_recipient]
]

COSE_Encrypt0 = [
  Headers,
  ciphertext : bstr / nil,
]

Enc_structure = [
  context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
      "Mac_Recipient" / "Rec_Recipient",
  protected : empty_or_serialized_map,
  external_aad : bstr
]

~~~~

## Public Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: TBD,                           / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'cab0df46...49467fd0',       / x public key component        /
  -3: h'a41a43d0...6d677a53',       / y public key component        /
}
~~~~

## Private Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: TBD,                           / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'cab0df46...49467fd0',       / x public key component        /
  -3: h'a41a43d0...6d677a53',       / y public key component        /
  -4: h'b780bb12...c77d9824',       / d private key component       /
}
~~~~

## Single Recipient / One Layer Structure 

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.1

~~~~ cbor-diag
[
  h'A20139D90204F7', 
  {
    -22222: h'04F9E269...051458AC'
  }, 
  h'4849CE69...E6982351'
]
~~~~

## Multiple Recipients / Two Layer Structure

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.2

~~~~ cbor-diag
... todo
~~~~