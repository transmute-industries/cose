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
urn:ietf:params:oauth:ckt:sha-256:VdyFfjROkcHkNoK-EMMf8WALwqFGhWTmmF6Pw1qp6fQ
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4a483853...45617977',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'3ac97116...0bd549b3',       / x public key component        /
  -3: h'058ea193...e9fd0a5e',       / y public key component        /
  -4: h'55eba5ae...49b43cc2',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:JH8SBDroFrpDCjkIDs7fWMKUXBTci9KioWxbKlnEayw
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "JH8SBDroFrpDCjkIDs7fWMKUXBTci9KioWxbKlnEayw",
  "alg": "ES256",
  "crv": "P-256",
  "x": "OslxFvjJi8Q3VqzOCmGuai80UHHa4GaUwYCeIwvVSbM",
  "y": "BY6hk3YMubUVuag3nueYHZsnjGjYh9kEg3rXPun9Cl4",
  "d": "VeulrvIYNEcBj9tI6QtTvna_k-zTtJdQWDs7Dkm0PMI"
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
urn:ietf:params:oauth:ckt:sha-256:s6_PBEL4ysfkuJ_PG4rpQcrgN4m4kyXsfeMEhfGLgt4
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'54547a33...45465349',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'6581b517...78be2d71',       / x public key component        /
  -3: h'd9840ee1...ecfccef6',       / y public key component        /
  -4: h'40fa6f7a...bc028bea',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:TTz3PhqM3UcgJm3t2hW7QPBWikqQs2LxbEN-njgEFSI
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "TTz3PhqM3UcgJm3t2hW7QPBWikqQs2LxbEN-njgEFSI",
  "alg": "ES384",
  "crv": "P-384",
  "x": "ZYG1F25iXC0SamtELJS_PDMw2b6m9LNlWwmD-todJhhSAHQ5Xm3lX7NQiah4vi1x",
  "y": "2YQO4Z4r9kR2xMKS6UPkuHftyin4D7GuAVaO8llvz7gMpBWawjvag4WGtWbs_M72",
  "d": "QPpvenMncvhEbYMcpSGgAdZNAITxanImtg0ehC0JCc2ppiU7Y-6nZTek7EC8Aovq"
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
urn:ietf:params:oauth:ckt:sha-256:h5EBU8fmmn3CtCLQuvS5zSdOJUmdAd6XtNawWHgKqag
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'5a68656a...78774e51',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'01680998...6b88c1d5',       / x public key component        /
  -3: h'0046c03b...097a8f2b',       / y public key component        /
  -4: h'017658dd...3c73a95e',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:Zhej4BwTZvjlYpK7Oo8e2x_PC6_j2r0FwewIGrCxwNQ
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "Zhej4BwTZvjlYpK7Oo8e2x_PC6_j2r0FwewIGrCxwNQ",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AWgJmLQCW0JHw7jjzArXrpbmoqfhiNvPBn0I5JYaORBJsCHcUWbiK3DUgfe0CePcIZ1-df7NsIKKdcNPuZtriMHV",
  "y": "AEbAO6J-TuDF-xgZn09koLPXHPClOWeZeCtWUaYoET19VJ07agBxjASERZkzPSpDOpywrln1cSLZtQWFhkUJeo8r",
  "d": "AXZY3UZnPZzyZJHPtGvM1vYCvgbHAB6L3LEA37Z8Jd_Q1MPstUL_vpoUvaSeGpUfEEUTYk319ud2bPfn3t08c6le"
}
~~~~