# JOSE

🔥 Experimental 🔥

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
  "x": "xXCWZk-jG9Tjd7M361sAEUi8JvKBxFIQgqhqkZa5cgs",
  "y": "y-9jpXy5gNhxl9BV4smqO36MXRlbkrC3PvvjDOrpOgU",
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
  "x": "xXCWZk-jG9Tjd7M361sAEUi8JvKBxFIQgqhqkZa5cgs",
  "y": "y-9jpXy5gNhxl9BV4smqO36MXRlbkrC3PvvjDOrpOgU",
  "d": "aRDKVwA-kwySgg9Z8jd9GsV-Kq2KoKlFAP79vbU7TRQ",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQkIyaUpkbzZQM3ZYVVBQbUNoYlo5UjdUd0Y3dVEzTUpySWFIaWZUQnQyczZUZmgwNG9MWi1KOUtpX19QOXhfakZEYW9yZ0xwLUJUSG1OSi1FdmpVeHU4Iiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "3239ChirVmfriy3SwN7m2SIpP8VgFoXxm1ZQ"
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
        "enc": "BGKO2-0oc4lsB4u2E3IK9kI0AVNqyZpDwssNBEkDr1MYjSTS6yB9rS8A6hrRUdXVPzj05UiierQAMojlgySoJgk",
        "encrypted_key": "RaN5dZFZR8Hr_CibbRiOPFkMW8ylue6lQ6T5cU7ZPtc"
      }
    ]
  },
  "iv": "DojoBowHRBbJLffK",
  "ciphertext": "Vuw6ChVjGp7inNdI-AiAQYq_3JvvqJUXAjjF"
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
  -2: h'c5709666...96b9720b',       / x public key component        /
  -3: h'cbef63a5...eae93a05',       / y public key component        /
}
~~~~

## Private Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: TBD,                           / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'c5709666...96b9720b',       / x public key component        /
  -3: h'cbef63a5...eae93a05',       / y public key component        /
  -4: h'6910ca57...b53b4d14',       / d private key component       /
}
~~~~

## Single Recipient / One Layer Structure 

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.1

~~~~ cbor-diag
[
  h'A10139D902', 
  {
    4: h'746573742D6B65792D3432', 
    -22222: h'048B1833...7D274594'
  }, 
  h'A05D4B87...3E99A6F5'
]
~~~~

## Multiple Recipients / Two Layer Structure

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.2

~~~~ cbor-diag
[
  h'A10139D902', / protected header /
  h'4F1EE8FE6B430057B83500FDC807EE679E0FE59F34B462CAC4AA8A', / encrypted content /
  [
    [
      h'A10139D902', / protected header /
      {
        -22222: h'04E8A00C...273E9D83', 
        4: h'746573742D6B65792D3432',  / recipient kid /
        5: h'B0810758588B262C0492BE2D' / iv /
      }, 
      h'E4FC6B69...FF449CA1' / encrypted content encryption key /
    ]
  ]
]
~~~~