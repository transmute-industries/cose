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
  "x": "2JStVF6Qnj_okF-tMh83YmHGloNG0YAUnUm7ft0EZNo",
  "y": "LFkWC9_frlU71b1yNKc7f_eAsosKCOuwZ7-3GjTo3f8",
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
  "x": "2JStVF6Qnj_okF-tMh83YmHGloNG0YAUnUm7ft0EZNo",
  "y": "LFkWC9_frlU71b1yNKc7f_eAsosKCOuwZ7-3GjTo3f8",
  "d": "aba0qLA8Usjo9-a_BCIQmpBpx0R8txWw9ghqfhNyU0o",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIiwiZW5jIjoiQkZvRnhpQU5KdnBNZ0t5dUlOdU0wVzhJTF9vdnQxTy1QUkZHTVdPcFByR3gtWTMzMEFHSDlKTGYzNDNRVFZzSXJZV2F4bnc4WHdvaVFfd1I3dk0xdWxvIiwia2lkIjoidGVzdC1rZXktNDIifQ",
  "ciphertext": "QlzHZ4vj-N2ZBqidEpzg6XKZ1tDGHsFntXnu"
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
        "enc": "BGSJWJGMxKF2eihNqjLfTS9TNPq43QwKJvQCJVRyqIMree-kM_bcF475OU0mqvIwt-IPp9PDdIVd2eVIeK2TuUY",
        "encrypted_key": "YwtPrU7hK7_j5QoFoWoyOaoAsVTAWCo8mtIrlU_XhaA"
      }
    ]
  },
  "iv": "ZJ-tN_AYmy8TtGsx",
  "ciphertext": "3_csqoDkolTdG3VgtG-sm7ZpuWYa0kG4_N8m"
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