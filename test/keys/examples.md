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
urn:ietf:params:oauth:ckt:sha-256:Q6NCHRxDeXONZt2x9we4ILqZH51b9WTzLWm9HhSus5U
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'33384732...4f736f4d',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'96a90a46...3264c8bf',       / x public key component        /
  -3: h'294445f7...252a2f3f',       / y public key component        /
  -4: h'e611ffa7...06245a8e',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:38G2QywuruV_Xv2b5mZTibt5_xtOODpkKDeAF_5OsoM
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "38G2QywuruV_Xv2b5mZTibt5_xtOODpkKDeAF_5OsoM",
  "alg": "ES256",
  "crv": "P-256",
  "x": "lqkKRgdIT-lFiY7VW7ACxMdsTmaD9CBUJUYSSjJkyL8",
  "y": "KURF9xOkwwEtBPyFdcYceEw4L-YJ8IO6P_BASSUqLz8",
  "d": "5hH_p1BmrESa6K6_5ynjWWz1ih9BxIqnCiPJSAYkWo4"
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
urn:ietf:params:oauth:ckt:sha-256:_P3rPpfFT0Xw4EvgwFiJaYw0A2V0Fwbx7FtrzWWBBGI
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'596a3176...74695967',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'f120379a...89873552',       / x public key component        /
  -3: h'cc6d8c18...564382e1',       / y public key component        /
  -4: h'93aafb92...bf8339f4',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:Yj1vUJ_7EbNiMA2ZvxbLSrkfcYNaYJmodyRBbvytiYg
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "Yj1vUJ_7EbNiMA2ZvxbLSrkfcYNaYJmodyRBbvytiYg",
  "alg": "ES384",
  "crv": "P-384",
  "x": "8SA3ml3miMopKkmw4jruuQ2qr5SeNmQiekfbOt-mWaQBjRJ1Q4wz9-5pzUuJhzVS",
  "y": "zG2MGJDBvh1YZA2dN66aibVSY9XrBQM3r09b0pz7tPDXxw_1b9Xk320HU3tWQ4Lh",
  "d": "k6r7kh4unN0h91HyAT_OemQ7zU6E1TnZ-JOO2IOK-CBKls1gOez1bwW86Mu_gzn0"
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
urn:ietf:params:oauth:ckt:sha-256:HzXLBQ1U2HIsxJ8LbdyPTvZ71XNQEcpoHTzHsI6cLvA
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4a564142...5a714c55',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'00ab2548...b4f0e9bc',       / x public key component        /
  -3: h'009c19fc...cd782f0b',       / y public key component        /
  -4: h'00d79368...f820135c',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:JVABImCU0jbwh1HxVwUVFqP9p5JsSyS9hSP_01yZqLU
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "JVABImCU0jbwh1HxVwUVFqP9p5JsSyS9hSP_01yZqLU",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AKslSKUtFwkTqE5tABrgiYVgrsF9EunCv_LvedLFBnFkMPUetMDG3-mbZ11P0ZHFg7Z24zfzOcJPdtiuEn-08Om8",
  "y": "AJwZ_C-1U4JhGo8QZBiESYmemwbVK9A5-bizaMEu154JzT4a_QN2IGKTqjwP3pQVBDlz4veFtqbMxUxlo4vNeC8L",
  "d": "ANeTaBm3Et5Feww55UiPP8NQFN_3JTS8sxWOgc6xg202Tt6IYBrw51F6riFhPAoO8kHmbTn8XBcguMGc6I74IBNc"
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