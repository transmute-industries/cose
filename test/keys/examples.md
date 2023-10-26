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
urn:ietf:params:oauth:ckt:sha-256:QYznSBzTde6G_cQFJNOf-mAZO5bE0AzJldknDtggYJg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'48544e65...44656c6b',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'9424deb9...8f6d74c2',       / x public key component        /
  -3: h'32d64e3b...1354510a',       / y public key component        /
  -4: h'2fd91345...00fcb339',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:HTNe6oV28AALooI_ClKF-ARejK3TCsjSwrU2pf4Delk
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "HTNe6oV28AALooI_ClKF-ARejK3TCsjSwrU2pf4Delk",
  "alg": "ES256",
  "crv": "P-256",
  "x": "lCTeuf2H2Ks5VQOsREiv-Ks9BPLLzOyTI0JkrI9tdMI",
  "y": "MtZOO1I1rtzU9OwKdqajEQ_rOc9D_wDh_25P_xNUUQo",
  "d": "L9kTRYnxuDnvgDMamThYyBe0EbipDUy6yCvTJAD8szk"
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
urn:ietf:params:oauth:ckt:sha-256:bjEiaPy_q3m68VI3TISxME9JPvxPaoRDHRC4bWaohxs
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'42316632...6f323567',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'08755f8c...bf7e9e88',       / x public key component        /
  -3: h'126d2776...47127afc',       / y public key component        /
  -4: h'a65c14a8...c70ab999',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:B1f2iaWwAukX2weITJo3M8eCbl83tcCaFtRE1ySo25g
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "B1f2iaWwAukX2weITJo3M8eCbl83tcCaFtRE1ySo25g",
  "alg": "ES384",
  "crv": "P-384",
  "x": "CHVfjB9v821GTA6IJrm0T3p0e3J0s4NWke6TCyE-L8IJr5whGww4dCSW_u6_fp6I",
  "y": "Em0ndqT-g5cv87auKUJT_4s8zoEHXGMyTKQGr5mhUjMRRrGhdlXk1bZBi4hHEnr8",
  "d": "plwUqMHcDTFEQuWP8G2Lqc4sK3esp8J4JXkFPXecrLGY77cybNRpVyjRt8_HCrmZ"
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
urn:ietf:params:oauth:ckt:sha-256:BGVMQeRNYfbx6qH5Fvq2FjC9u_4JTmT7btmW1_HBJWk
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'41393159...47677155',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'019da3f9...e7c10897',       / x public key component        /
  -3: h'014ebe01...ba08aa9b',       / y public key component        /
  -4: h'00faae8a...a35fe835',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:A91YMIJqs_0vF_aLwzO-_Vpzddf2vnXinjHeydvGgqU
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "A91YMIJqs_0vF_aLwzO-_Vpzddf2vnXinjHeydvGgqU",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AZ2j-au-rX2a-4zxxWrY3NB6UBMNHiTLUZfUa1T-J8zoWPflD_rYiKJWFhP63a9Ry6NcYFEa-fQVKR1uvWrnwQiX",
  "y": "AU6-AU6aMYuZcAvTqhDWdSnm7aQaL7OpimxLEzo1tFdj6t-b443P8evHQ5HEamwLVR6-xG19ZnpWEuDDZ6m6CKqb",
  "d": "APquijnVG14JdIoolZehDXF_6VBNlNHEc3zQUygTcW8avdRJKt3mQxftwlX_8M7efQXYBCPBFTx1vnVyRy6jX-g1"
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

~~~~ text
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