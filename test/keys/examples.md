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
urn:ietf:params:oauth:ckt:sha-256:1g28vYUpKVm2hIdew-qgNpKCHSz7R4DlfXes_pcrg2w
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'345a6b50...4a506473',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'e14a54a4...7bb7991f',       / x public key component        /
  -3: h'660781aa...b699cf80',       / y public key component        /
  -4: h'921e6ef5...000195f6',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:4ZkPqJeFc9BX82Pb4PRMNEzT8KWAEZs_rU2zukoJPds
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "4ZkPqJeFc9BX82Pb4PRMNEzT8KWAEZs_rU2zukoJPds",
  "alg": "ES256",
  "crv": "P-256",
  "x": "4UpUpOpFx9U-TLa8nuL8RDFrp1vcRqvPiLYrgnu3mR8",
  "y": "ZgeBqsMITPNEo-qUufW-LIiI1kFpCoEvJU48WraZz4A",
  "d": "kh5u9c_XRrShvU08aI4EcjwE4WIDwUMOQADgTwABlfY"
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
urn:ietf:params:oauth:ckt:sha-256:qnsh6IV4ppOwrrvZiXJbnRqCdEt5md2VAyTfBIxbDm4
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'732d7633...4a653434',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'835e747a...5507d423',       / x public key component        /
  -3: h'8af49c25...02c86afa',       / y public key component        /
  -4: h'8a72e3de...df60a3f8',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:s-v3XcM75xdFYIe-Ud8nYzZSIsb9yxIvh9eaTeIJe44
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "s-v3XcM75xdFYIe-Ud8nYzZSIsb9yxIvh9eaTeIJe44",
  "alg": "ES384",
  "crv": "P-384",
  "x": "g150euFuW64nKC-YHYZK5TgXNwq42Lh5EmEg70tklODccoc9h06dvlbBOKdVB9Qj",
  "y": "ivScJUCWbyT8fUgxulB90Cdw0LdMnRmSAJUKM21KRUj0BP_csMrIBAYrAMQCyGr6",
  "d": "inLj3nnJO0R1HjgzlyQnUKIije2sDObip-uopxeFlsuyc4MsYClw4490NQXfYKP4"
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
urn:ietf:params:oauth:ckt:sha-256:2J8DpHy1snTd2lP1t4JLWRF4RmRqaZNz48urMG0CrSU
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6f4f3745...4e505434',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'014c6f77...372da365',       / x public key component        /
  -3: h'002b9089...5523c61e',       / y public key component        /
  -4: h'014166b6...779e8929',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:oO7ELz-Zvzc6adVrj8t1j4UIo7UYXl2WaEOYpN1NPT4
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "oO7ELz-Zvzc6adVrj8t1j4UIo7UYXl2WaEOYpN1NPT4",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AUxvd2_Qw9aq-nI1WUW6fGqS7Q53AA3Qynju5InxZpHaYNRLt0DkqDGRi2rkEfpmQ_skPTE6dtdxGHvhh643LaNl",
  "y": "ACuQiRKcTbZHHYBMEfv4ZPiLL6inGwyeTah8MaJ60QNqB8tPErR7I1TDuAk7_hVQvq74kR8wDw1II1NXqQZVI8Ye",
  "d": "AUFmtseg1cTLMsu9QOFmra_VsJbO_KyTUqS4SmRVIrZNVXCb-rK6j8ZW9z3bJfhR1gt7tPzhjWCRuFQw_NZ3nokp"
}
~~~~