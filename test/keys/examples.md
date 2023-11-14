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
urn:ietf:params:oauth:ckt:sha-256:MNRLUimqc4-gReSsygv6ZYifBqKHZg9vhV-euZwnBZg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6a464d4d...35577845',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'b044e030...38214ea8',       / x public key component        /
  -3: h'fb5a856c...fe499b52',       / y public key component        /
  -4: h'e55c01d8...dca598d5',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:jFMMcx0W2qi6R03uWQC9TDRfUBdHqDkwZcyJ7CF5WxE
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "jFMMcx0W2qi6R03uWQC9TDRfUBdHqDkwZcyJ7CF5WxE",
  "alg": "ES256",
  "crv": "P-256",
  "x": "sETgMHvmyRKhmEGVkBFWCWBh-KQCyiBfh2haFDghTqg",
  "y": "-1qFbMPkSQb0KBtMPKZqCYLzzZIxXo0PdBnqv_5Jm1I",
  "d": "5VwB2AJC_GOqrbOmsQu6RnOOvzr2HSWxZhbf39ylmNU"
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
urn:ietf:params:oauth:ckt:sha-256:iRqBxfMorVacQ34kNxFFL3XsPMZXs-mkPqaLhRwWm4U
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'42684166...64776d49',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'a8fc09b4...85a03dce',       / x public key component        /
  -3: h'7b85c673...573a695d',       / y public key component        /
  -4: h'7f6486fe...08438f26',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:BhAfDtavl9FyxN_MoHhv25g91SQ1zBFNJJ5ajGAdwmI
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "BhAfDtavl9FyxN_MoHhv25g91SQ1zBFNJJ5ajGAdwmI",
  "alg": "ES384",
  "crv": "P-384",
  "x": "qPwJtDxmtOU0Eua1mc867FtoWuwgzPueLiyXHCPd5f5yWzT7xnDKDp_AhreFoD3O",
  "y": "e4XGczw6_BMNv-ob53xI6NjDDorh_hQ7T-cO1pBMtgF0f-DzIpRAoNfYD3BXOmld",
  "d": "f2SG_niM84ubnXK0UJmI2gP-ml_evr5OjDLYRrjbQkLs8WFvctkswjvfHwEIQ48m"
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
urn:ietf:params:oauth:ckt:sha-256:SXt86uhKfa0g1Sp3g4KtKOJzB6_jMuVhAAMaYVXv624
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'7533464c...41356c41',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'002cc49f...4631cd88',       / x public key component        /
  -3: h'00b13ff1...edf6f732',       / y public key component        /
  -4: h'00f221e4...d1bfc9a7',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:u3FL91I8n18867r4lzxofxVjGkJZIgXq0OpenLCA5lA
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "u3FL91I8n18867r4lzxofxVjGkJZIgXq0OpenLCA5lA",
  "alg": "ES512",
  "crv": "P-521",
  "x": "ACzEnxsG7ulvtfShF2SOddspeLYGt_FueW_HyNu8a8vps5xN7op2rqCe9nE419tv3EnpUEDBRl1hjuNPxgZGMc2I",
  "y": "ALE_8TTsMJK4dzDQULlltjcLSx2rz9n1JOvH5fdbAU6lLs8d6ZQNQhlfrgGpHtjDSsSKQ4_T69mZQEPNhPnt9vcy",
  "d": "APIh5JGXMLxfG1KRnvuVhv5qmwZg2__J46X7MPZpp4bPysDPF1qLW2E7JUYl3kEeBho8_QskStbA-EekW6XRv8mn"
}
~~~~