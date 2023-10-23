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
  "x": "I-56LdxhSGHqJP-Kq9geT9K6raTe9Jao3oD2JEHhvQY",
  "y": "bffCG9dOnJoKG3lNVs11RprI_FYFfTguwAkqZ9rzfS4",
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
  "x": "I-56LdxhSGHqJP-Kq9geT9K6raTe9Jao3oD2JEHhvQY",
  "y": "bffCG9dOnJoKG3lNVs11RprI_FYFfTguwAkqZ9rzfS4",
  "d": "txWSMYMJH1EqKz5veMoxmRCZH4g-92tYOEJOqPsiJ7I",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQkpEVi00WGJrWUxmcE05UnNZZDdoY2g4STJWZEszWWFZYVBvQ1FZZENfelZleFV0Z1NDel9XLUpXMFc4elJyaUFjRmg3VjhVRHNqcFVXM01OU1d1QXNVIiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "mXphyX1NlrBLtbS_xo21jMsO7tSeR-P8Yg7j"
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
        "enc": "BHxnDF4bWzoQeQ__rRUJ-4v89ZVphGbK-2te_PdcGMMxW5a8ARRNpsWAF3bTNF4w2hMTozwXCYl1EaEkMlZJ2NM",
        "encrypted_key": "sgEoDPExIgpS6BNGaV2LLwi63QwnkDWKyYBqSrtHpfA"
      }
    ]
  },
  "iv": "Zf70hrB_LxMA0RQ8",
  "ciphertext": "-VAKR3tNcm3uafNnh2alIcrc5bIjdhFvWKzJ"
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
  -2: h'23ee7a2d...41e1bd06',       / x public key component        /
  -3: h'6df7c21b...daf37d2e',       / y public key component        /
}
~~~~

## Private Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: TBD,                           / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'23ee7a2d...41e1bd06',       / x public key component        /
  -3: h'6df7c21b...daf37d2e',       / y public key component        /
  -4: h'b7159231...fb2227b2',       / d private key component       /
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