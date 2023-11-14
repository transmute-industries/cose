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
urn:ietf:params:oauth:ckt:sha-256:OOD-JuVXujvxdDWa-XRzsvuvXkWzdJJWhILM3RFK7U0
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6462736d...55515f34',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'3f9214cd...b6ee9947',       / x public key component        /
  -3: h'669a45ea...8a898ac6',       / y public key component        /
  -4: h'31c37dc5...2fa9e746',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:dbsm46fMlRPScVGms8rikUuHhQht3tY9aIhXtc9UQ_4
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "dbsm46fMlRPScVGms8rikUuHhQht3tY9aIhXtc9UQ_4",
  "alg": "ES256",
  "crv": "P-256",
  "x": "P5IUzYZfGrcmGRBjbJbuZU-LakRdtgUpK7w5ZrbumUc",
  "y": "ZppF6ld_ulxB1pdT-0v6hkreNE1_wz4MSJZud4qJisY",
  "d": "McN9xR5DA_3hPQltboOytVCL6jQn_AUhB0ZKvy-p50Y"
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
urn:ietf:params:oauth:ckt:sha-256:qOW-16yIIF-31ET7ezUO2KJWyifNkvdjPskDJFELNAM
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'63374d36...4a485051',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'4b52051c...2c67d4b9',       / x public key component        /
  -3: h'6fe9a4f3...87419be3',       / y public key component        /
  -4: h'45ef82f4...02490d1f',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:c7M6siwL8V6O9p0qIlNXc7lX7cxiaYYJZOaqO4bJHPQ
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "c7M6siwL8V6O9p0qIlNXc7lX7cxiaYYJZOaqO4bJHPQ",
  "alg": "ES384",
  "crv": "P-384",
  "x": "S1IFHDbRvsClsnCSG2QvNCDbN4mW3ze0XZWSAQ4Pbpje0i-xg2wXlVQra9QsZ9S5",
  "y": "b-mk89wRg2kmsQxTuwBmWDyTp9sbptK_kH4Zu0xpxtcwF0L-K0QhLtKvySqHQZvj",
  "d": "Re-C9Aho2Yn5606g-HSxaIKuksDT9X4hxK05blUJqXJMHv5NvTk6WixwFNgCSQ0f"
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
urn:ietf:params:oauth:ckt:sha-256:FEBsYeD9kliO_dJFKKUZd8S1q9B6XA7ZEEDZdCq55jM
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'556e7251...5f623338',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'000e782e...985d520b',       / x public key component        /
  -3: h'00f0a6f7...b917062d',       / y public key component        /
  -4: h'0008a6cc...3f59c090',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:UnrQ0s7n7Qf52AcKWNAEskGIWZAn7YWyEnrOLjq_b38
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "UnrQ0s7n7Qf52AcKWNAEskGIWZAn7YWyEnrOLjq_b38",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AA54LmOHe0bFCr3nBRdLn5kPNZ1se2NLhNyk2sKW2HnmVqo9eFuj9L3WIzmVkzvMpKUopbhZtvgUkj-OsrmYXVIL",
  "y": "APCm95Iyu9od4YYDdlTQTdUhb0DS_Zxral06J4kZLkujsu0InIYsXbHNybvVBGD19cHnSOYP7-H2GGAwS8W5FwYt",
  "d": "AAimzCUumY7NbgBd80R3TjfAMV0yE42z5fSmo9HchDHUTK8AoRkv73UsHnzNMNKjd6t0Sg1Jm8BTU6U8qAg_WcCQ"
}
~~~~