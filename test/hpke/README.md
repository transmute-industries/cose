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
  "x": "oqhllhz4-baJW1L_UqDxjLVgMoRXJ5Alfj40fD-2BnM",
  "y": "0hPPe-G502BE_e_JUociO3xPiZBCQIWjxJOszxE5dVQ",
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
  "x": "oqhllhz4-baJW1L_UqDxjLVgMoRXJ5Alfj40fD-2BnM",
  "y": "0hPPe-G502BE_e_JUociO3xPiZBCQIWjxJOszxE5dVQ",
  "d": "oneFyqTlPPrf_RjnakaErkR_wmjtVNlleI-8zXjKLIc",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQkIzM1NheGZ5UU4yOGp5YVdnWlc5aU1ueTZQdzR0b3A5VVRsbXMybERJSmVoUG51bXJJVlFNVXBySk1WYldMdmo4R1F6T2MzWVVuREJtRlFaeXZhV0hnIiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "d6ey_nLzclQFSYCrr0djKtkgdjp5YiTeTG7z"
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
        "enc": "BO5OwgjG9OGQcjmktVxpPR7ZQW4VbgZCriYClTVZPxPiiqu-l-iFZFMkGgA-Ivnuo_VPWaiV5ZJBb15SYqGaZN8",
        "encrypted_key": "sWjcksMGxC47UZdMEc45o2IfboZkreU3zjgyYeiDHCQ"
      }
    ]
  },
  "iv": "NawPVdYltkxpZHoK",
  "ciphertext": "8dKQrzma2zAqzH37AB6n3e6IBnUMF7VyvspL"
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

... todo

## Private Key

... todo

## Envelope

... todo