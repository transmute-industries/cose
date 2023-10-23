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
  "x": "v9WjH3_9biEyYEtx6BoVsEm892fU6I3XbtiI_Z4xmHQ",
  "y": "Z8P90xAUdtWS1rEcph4z_iA6azhX-yiCTrw0CR_SAmw",
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
  "x": "v9WjH3_9biEyYEtx6BoVsEm892fU6I3XbtiI_Z4xmHQ",
  "y": "Z8P90xAUdtWS1rEcph4z_iA6azhX-yiCTrw0CR_SAmw",
  "d": "De_RiPnWlHWWINY5Ow5_FtrHbE1drRKXa_8aSl8DWxU",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQkNNT2Z4M2pvNTQ5elNJX3Y2aVdHMl9qSUJpaGhqaW95VlVxOEJZWklNYnFndDRYaG9VM0hseHVhaUNnRE55SXo3cVdMU01zR2pBYmJNeV9ZWXlzUlF3Iiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "bkA9KB_cnSBYalCV8XBrBaEIkFWYHyrJHCwA"
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
        "enc": "BNFJG2WvuAOS1yaD2D-KAhOEUhdvQ1g6-SKb50hQKMyu455BkHk5-753LMOv1pMid0AZN9xuMBUJZCw1_qpUWlQ",
        "encrypted_key": "LQHOvwT1jAFi0rbQXGtWZXwbVDOxl9z8LF27xHZ9TAs"
      }
    ]
  },
  "iv": "31UpLo3e71zG5Ocn",
  "ciphertext": "BnSmv-tQ0F74Tih0br-to7gy9OT7Nn86ZQs8"
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
  -2: h'bfd5a31f...9e319874',       / x public key component        /
  -3: h'67c3fdd3...1fd2026c',       / y public key component        /
}
~~~~

## Private Key

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74657374...792d3432',        / Identifier                    /
  3: TBD,                           / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'bfd5a31f...9e319874',       / x public key component        /
  -3: h'67c3fdd3...1fd2026c',       / y public key component        /
  -4: h'0defd188...5f035b15',       / d private key component       /
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
      h'A10139D902', / protected header (repeated why?) /
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