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
urn:ietf:params:oauth:ckt:sha-256:BOSZSJ0xKHMecqA7zZ1P5nb61sdpOug5DDm08RdUr9A
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'74704b76...59565a63',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'a4725ff9...ca65f639',       / x public key component        /
  -3: h'b6f61758...08b3e9ba',       / y public key component        /
  -4: h'c977ed33...9801a780',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:tpKv1rOPGAqKyhtBC4Z6FPDgSYMwrt7su8yoiYgYVZc
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "tpKv1rOPGAqKyhtBC4Z6FPDgSYMwrt7su8yoiYgYVZc",
  "alg": "ES256",
  "crv": "P-256",
  "x": "pHJf-e_ddBsnbavnOOJAufI9KgTUF-_tZ3L5D8pl9jk",
  "y": "tvYXWH4M3o9X5a1nrVU-vPa3URTo8QlddZYUGgiz6bo",
  "d": "yXftM9XJu1LDkbF3DxrSSUbRy5PNr09Fbskj_5gBp4A"
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
urn:ietf:params:oauth:ckt:sha-256:0zmk1A7RldKfBHaaA7zuHceFxcjwQHAkw9rYp-sxoZw
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'44736545...6d504249',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'e68ee849...27ee94c6',       / x public key component        /
  -3: h'a1db3cb2...5ed82927',       / y public key component        /
  -4: h'7d229ea1...f4ce72af',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:DseEfwsY_WgFXcnadulosVFk_O3SATgjHHtzh0dmPBI
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "DseEfwsY_WgFXcnadulosVFk_O3SATgjHHtzh0dmPBI",
  "alg": "ES384",
  "crv": "P-384",
  "x": "5o7oSdNuLQiT5W9SvMAnWtBu1jKnErkpg_Ph_FnkonhbOR-kE3kU4WCigKcn7pTG",
  "y": "ods8sl2kHwan1nFjOs3hyk8uew2p7ngMJXm7aoGMLM9yiCfAi-fJu-B8vb5e2Ckn",
  "d": "fSKeobGLtio-SNRcAVy4iyWXwU4rrPbgnlOE7eQUtiRxE95gVm9y7L_8h4v0znKv"
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
urn:ietf:params:oauth:ckt:sha-256:WjKsoGUYFptXLxC0SG4cvkGau3bAFx2svWLnwguNCzc
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6c70515a...7454526b',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'00639eb3...da348de3',       / x public key component        /
  -3: h'0085bd9b...7eda550c',       / y public key component        /
  -4: h'00ed041c...7bcaa9f3',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:lpQZ-748lee-iIfr64K1FiMJdkImogtRe9wLuTqtTRk
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "lpQZ-748lee-iIfr64K1FiMJdkImogtRe9wLuTqtTRk",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AGOes1DJjj8q2ddXBI_KbS02SHNlonrr98cBUowSYcrPm2ZREKkPwrR5RKDtJqQp3T7dJPX3Ba1O5_Q40ovaNI3j",
  "y": "AIW9mzs84fyp-YteThL0a5fojqQC4XeGzn_G2RNgno_O303hSwfaxpmlg-PGLvKAVMeNrJBnufX2ZDbSzeR-2lUM",
  "d": "AO0EHLlCT4adWFEB1h6ytnGCIrvWXKf9HNIx4Aq1GEmLr1VQg5PmV4aLaxQwVPvgV11TUwYtQOqtTwpqEKF7yqnz"
}
~~~~