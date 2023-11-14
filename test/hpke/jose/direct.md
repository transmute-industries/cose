# JOSE HPKE Direct / 1 Layer

## Key

~~~~ json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "HPKE-Base-P256-SHA256-AES128GCM",
  "kid": "test-key-42",
  "x": "8t5UU3v5QuAUXucu08rdgjSoasS-UzR2as-wJcBFHxM",
  "y": "CjzCqtbQUBkneLu6NrZJOinBsvr-Ywoim_WxdrruPz4",
  "d": "TjIUCU7eiOa4-caHJCUcjpaeF64QHt8k_XOUuPmZwFo",
  "key_ops": [
    "deriveBits"
  ]
}
~~~~

## Envelope

~~~~ json
{
  "protected": "eyJhbGciOiJIUEtFLUJhc2UtUDI1Ni1TSEEyNTYtQUVTMTI4R0NNIn0",
  "unprotected": "eyJraWQiOiJ0ZXN0LWtleS00MiIsImVuY2Fwc3VsYXRlZF9rZXkiOiJCSlRpdWUtZGsxQzR3Tmx0NGFMcTdmWkRlZnhmdnYtWU1KeGNELVF3QVZlN2lkNVNvUG1hOU9TaEpTSHQtTXFQZVczYkNDWERDOTB2TU9Bd1RKWndXUDAifQ",
  "ciphertext": "QQ6AHA_yHm4-RTSo2gelPpfOu8UKuUKicM1y"
}
~~~~