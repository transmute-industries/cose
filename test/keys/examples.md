``` ts
import cose from '@transmute/cose'
```

## ES256

``` ts
const coseKey = await cose.key.generate(-7)
```

### EDN

``` ts
const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:ApCoXJgnHzOYjXwn5iHz0uNsBycwcM1V_yjOMe_0bjY
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'32596455...466f574d',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'94ebc004...0928ad6a',       / x public key component        /
  -3: h'34e96bd5...a1892d02',       / y public key component        /
  -4: h'a1bb67b3...00b491b5',       / d private key component       /
}
~~~~

### JSON

``` ts
const jwk = await cose.key.exportJWK(coseKey)
```

``` ts
const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(jwk)
    ```

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:2YdU5y7-wr_6j3rmIhpgN-TK70cnOidrJuXJvZvFoWM
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "2YdU5y7-wr_6j3rmIhpgN-TK70cnOidrJuXJvZvFoWM",
  "alg": "ES256",
  "crv": "P-256",
  "x": "lOvABCOvyrtzhCghszBxHXYruQmidXeE5TiH2AkorWo",
  "y": "NOlr1RjkaQYD0sBJ5ZbfEutgPVUKFMA9p_RdkqGJLQI",
  "d": "obtns0DUL5qLSSHfbb5UryVzNzGoBmS0RbmBnwC0kbU"
}
~~~~

## ES384

``` ts
const coseKey = await cose.key.generate(-35)
```

### EDN

``` ts
const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:-b4rDuSR60r4RHdjibqu79lhHH3hbfou3GBAewCmF5o
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'592d4265...64643667',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'aa3f89dd...a5c6c124',       / x public key component        /
  -3: h'5f306583...3fa940b6',       / y public key component        /
  -4: h'4acd756e...bbf962a8',       / d private key component       /
}
~~~~

### JSON

``` ts
const jwk = await cose.key.exportJWK(coseKey)
```

``` ts
const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(jwk)
    ```

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:Y-BejDSbAZWcMEbX2YMH__MB4Cpqb8OLQ0kbkJYdd6g
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "Y-BejDSbAZWcMEbX2YMH__MB4Cpqb8OLQ0kbkJYdd6g",
  "alg": "ES384",
  "crv": "P-384",
  "x": "qj-J3evo-apmELVRfyCUsd5kaDQ-JJKsI22u8V4NeRfxotzYbPNPX0Yrk3OlxsEk",
  "y": "XzBlg4nsyOoQ-Bs6BcgGGocnyHtJEJKldYYZD5zbJeFKDBdjcaPADh2I150_qUC2",
  "d": "Ss11buNrRLIYGH4GvXuWjwZVKuG05sq4uge9vbOS1Uj1dzGG-qHAsVJjD4m7-WKo"
}
~~~~

## ES512

``` ts
const coseKey = await cose.key.generate(-36)
```

### EDN

``` ts
const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:pnnarO3eaExhZEaVlE33nSQsLiGSHZymsrZNw2wM6gY
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4b347846...43723538',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'01b7f094...e2ddb7f4',       / x public key component        /
  -3: h'01489df2...47c21fe4',       / y public key component        /
  -4: h'00cb0ae2...aa4d0834',       / d private key component       /
}
~~~~

### JSON

``` ts
const jwk = await cose.key.exportJWK(coseKey)
```

``` ts
const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(jwk)
    ```

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:K4xFjQorgxqApo6GZ6HWh1Ztge5xwWwWfye7npgCr58
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "K4xFjQorgxqApo6GZ6HWh1Ztge5xwWwWfye7npgCr58",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AbfwlIPo4DtYJHXnzj7TGEMm36-USH_SgNoqaKs3cUiWOgARPUBf6yBSszV15NNSuOV8RFo_GHkLzp6402vi3bf0",
  "y": "AUid8hVJTzvOJFuPMAYEt31FpWLfyYodMwTCuB6I9rnKGEn0d3zl5I_4rncn-jGbMN1PaDdV6unvSNrJfQFHwh_k",
  "d": "AMsK4gaUAkPp8UT67sO2joSqnkuL5DXkNhRvoKPrtojHmEASFeR8Pa2GVEbf55nzb_oWFIKw4r8OQDqyMO2qTQg0"
}
~~~~

#### x5c / x5t


~~~~ json
{
  "kty": "EC",
  "x": "RFFp7pyHz8LNwfzv5Nm9Gj54KRena0ppOP97xwmk11qRks5ETTr4EPizXexJilPx",
  "y": "DCRpyw6zW8nWeje3tl2KKObt9_vUBVD1uoSEp-kNRzYB3Hfo6DVRgSqE28l-nf1p",
  "crv": "P-384",
  "alg": "ES384",
  "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tsuna-Iyuwy4T_HuTuT8kTGGc7yqmiqinaWkWfmKuZY",
  "x5t#S256": "y3aITzjZWqXeViSmaCmVyNTllEMkFUSrP3AidYCsR90",
  "x5c": [
    "MIIBtDCCATmgAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowIDENMAsGA1UEAxMEVGVzdDEPMA0GA1UECgwG0JTQvtC8MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERFFp7pyHz8LNwfzv5Nm9Gj54KRena0ppOP97xwmk11qRks5ETTr4EPizXexJilPxDCRpyw6zW8nWeje3tl2KKObt9/vUBVD1uoSEp+kNRzYB3Hfo6DVRgSqE28l+nf1po1UwUzAyBgNVHREEKzAphidkaWQ6d2ViOmlzc3Vlci5rZXkudHJhbnNwYXJlbmN5LmV4YW1wbGUwHQYDVR0OBBYEFBVkRlPB9mmvVdhL9KiFgd0MgWvkMAoGCCqGSM49BAMDA2kAMGYCMQCVStwHFVyaI9StLb96ToC8g5YG+q5j4vHVfH+EmQYfNuWa04JY5ZRw6NhLcdbQr3oCMQCRgwhMlxhn6d4oZ2w1Efd3uTIPcHt4g+EehMU1bEI7+x6i14w1SMWbU6vSh7TpsjM=",
    "MIIBvzCCAUagAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowEjEQMA4GA1UEAxMHVGVzdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABOsqL0satR5HAQ0+vBJKMlTv1cYQ0rg5I5z3K98GaEhxSUSvB0bk4Nf6VFOYyu5IS4lunr/XLmt/VIAWe/5qyisFQytWsiMzulXtVGxQ4pCbh1HTQ2dmRdg0WSU6pB0GtaNwMG4wTQYDVR0RBEYwRKAfBgkrBgEEAYI3GQGgEgQQrk8d+Ox90BGnZQCgyR5r9oYhZGlkOndlYjpyb290LnRyYW5zcGFyZW5jeS5leGFtcGxlMB0GA1UdDgQWBBRbPYmz753IRbpu0BWh/VGCgqf/qTAKBggqhkjOPQQDAwNnADBkAjAWGMj/8vkLoAXPkqfDRuHOZTxWMHylpUsqsnkGR2tNh8xNZDXzFQvzdafFUJqvlS4CMA0cUi/RJC3ff1x2if6Ua8jMTdh76BXBMxTDZehsu4ShdeLhbtJT9cHMIU7PTrX0LQ=="
  ]
}
~~~~

~~~~text
urn:ietf:params:oauth:ckt:sha-256:Tm3huDVZp7nlXlJG5DzkY_NvhOAf8R-qZ_PiZwtLc5g
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'75726e3a...4b755a59',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'445169ee...498a53f1',       / x public key component        /
  -3: h'0c2469cb...7e9dfd69',       / y public key component        /
  -66667: h'cb76884f...80ac47dd',   / X.509 SHA-256 Thumbprint      /
  -66666: [                         / X.509 Certificate Chain       /
    h'308201b4...b4e9b233',         / X.509 Certificate             /
    h'308201bf...4eb5f42d',         / X.509 Certificate             /
  ],
}
~~~~