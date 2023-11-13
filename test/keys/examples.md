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
urn:ietf:params:oauth:ckt:sha-256:A5mKy8KJS0njO7hKkCtWvG8rTv3SiMubxcqDSIj7kts
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'3930426c...65504f77',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'8e5d6e92...4e33f253',       / x public key component        /
  -3: h'f2b0a8f6...18d80081',       / y public key component        /
  -4: h'8a25cb09...181a873b',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:90BlaJVRjTe5jTt8O6j1wdhYTwplTvLW8GJkHmMePOw
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "90BlaJVRjTe5jTt8O6j1wdhYTwplTvLW8GJkHmMePOw",
  "alg": "ES256",
  "crv": "P-256",
  "x": "jl1uknVEoN9hYK-U91nJG-Z3eNTfuI82b_x10E4z8lM",
  "y": "8rCo9vupTQVD6ZoY-UYW7xNbswqMw0rtxLYgTxjYAIE",
  "d": "iiXLCf0_kdHqodoDsRxgc8bwfLWkuARx9NwoABgahzs"
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
urn:ietf:params:oauth:ckt:sha-256:5sGfjURszE_m5VgIKaYCrvdOfN5NxoxBXypJBaNjngk
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'63455762...32754438',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'858ab647...d0283817',       / x public key component        /
  -3: h'2a9a7374...d76f766e',       / y public key component        /
  -4: h'797be105...f98f0676',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:cEWbhDxofkC0rJFavvbkXZier2xKK1adNplo6Rn2uD8
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "cEWbhDxofkC0rJFavvbkXZier2xKK1adNplo6Rn2uD8",
  "alg": "ES384",
  "crv": "P-384",
  "x": "hYq2R7b28dR8W6S8Uf4tf3_lPPCxU1ym2d3XucYK5tPaHSEqoZKfy4QECMrQKDgX",
  "y": "KppzdDAG0qOIjP-Mi2Mj19YZaEi0r2OI4m94FPmlcIg3R7yBrwukALdUd1nXb3Zu",
  "d": "eXvhBcEUwxa9NGu35IjuQhcG4Ep_FQgQhHoVp1YlCTgdYeOXRRin7D4A5Qf5jwZ2"
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
urn:ietf:params:oauth:ckt:sha-256:yZsJ-9NZkn0OrZlXLvWswwy42G6meb6mhWAW21IRUl8
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'684d7363...35677338',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'01cb1951...7e80a986',       / x public key component        /
  -3: h'01364e2c...950bf42e',       / y public key component        /
  -4: h'01179e40...5b68d7f2',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:hMscb8I_cb2n5xkLtuEI0R-xMSM4L6YVdiw4GdR5gs8
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "hMscb8I_cb2n5xkLtuEI0R-xMSM4L6YVdiw4GdR5gs8",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AcsZUdqdM6xPwIOF5Gy7ntE3U6hgClh9KUZVidjge7lA9l47jkzGHe99wdicC0o4HM1Fu1mFE0TJEOyiue1-gKmG",
  "y": "ATZOLJ4w9dRG3utAx3x5XxM010Ocf27ZYz9HduWUPGX12Ih-eBK7slsSwu3mmHLKb6W_QtbMWUcBJ8e81s2VC_Qu",
  "d": "AReeQN3RxVKtwzuVviYhoBtgj1Ixfhh0TpiK9SmF5uG231sIK_jAY8Sru8IzRV4pOcWLSc0oM2Jpsx6SQBRbaNfy"
}
~~~~