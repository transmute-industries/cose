# JOSE HPKE Wrap / 2 Layer

## Key

~~~~ json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "kid": "test-key-42",
  "x": "lsXZ_lwhIBIc0dW3ks0rV3EZ9VMVyjYaekvWK68AYoo",
  "y": "cvAUoZjijHciEzsq_VqNL8Ro8l0Ar7DpDyarJqpfOYI",
  "d": "vQLn9va9Jiou28NcSw-Z8KVNWSJnOkklAxxO6NGqBsM",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## Envelope

~~~~ json
{
  "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
  "unprotected": {
    "recipients": [
      {
        "kid": "test-key-42",
        "encapsulated_key": "BCCIxjGW6CiQ2eiwJ5uvZFCSscZzn1L5kN3TDh3Mx_PK-ea3ty1b64m-iiuL-c_Rn0YRdOcmlZj14KuG1qPZVOA",
        "encrypted_key": "VR8HuShiBsfWAYBBGx1hSpRxF4lsn6nBnwYONHlxrdM"
      }
    ]
  },
  "iv": "gpOdvKgXRb7sJqWV",
  "ciphertext": "5ijhTOQ2ai-X1ovcVkc_cQjXUaSH9ZUAXSHm"
}
~~~~