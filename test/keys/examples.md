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
urn:ietf:params:oauth:ckt:sha-256:lC-GkAD3bB7V6gyzn-WknVx0z9TvcgaAnRYoFKBz7zg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6b775163...61523267',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'd69ce680...8383f9c7',       / x public key component        /
  -3: h'40547ca1...c9c347bd',       / y public key component        /
  -4: h'6caa6281...c06a086e',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:kwQc5cZuilOCixNhSdyPTwkEEHC8Dkx3Q0bKG_xaR2g
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "kwQc5cZuilOCixNhSdyPTwkEEHC8Dkx3Q0bKG_xaR2g",
  "alg": "ES256",
  "crv": "P-256",
  "x": "1pzmgGW4rNVZCbPcmYB8py_foFGI_tEENi3OR4OD-cc",
  "y": "QFR8oRcJIjWUy7CATs-TsSYojg-cTrCpunurrcnDR70",
  "d": "bKpigThFV3kenefjzxVZTxI75vgZiKCG-FqLacBqCG4"
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
urn:ietf:params:oauth:ckt:sha-256:JKyHJ9DlJF9GcgNvjEe53IXZCsqqKeGMK13LWPjI50M
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'674d4a56...74796134',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'd05a6096...87943299',       / x public key component        /
  -3: h'7c6e5a3c...85ef3625',       / y public key component        /
  -4: h'a8fc80ed...c8fd2a8b',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:gMJVOwztvWZ_0F09QApMClN_ynwaDp-sF0khbAktya4
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "gMJVOwztvWZ_0F09QApMClN_ynwaDp-sF0khbAktya4",
  "alg": "ES384",
  "crv": "P-384",
  "x": "0Fpglh7gTVwrGMCfghiN13mRmK0Uaq2UoZMUosKWsAiEE6ZPnbfk9XG13ZSHlDKZ",
  "y": "fG5aPCa2Ud_YDghvQN0kUy5Lfxccv9jN5UkIjtewW7tpTNYVBHZBiTaOXQyF7zYl",
  "d": "qPyA7TXpnJX9JrKihyyza8BNmf6KJr_UvVHbr9YVuXLzqcMzyxE20pQXyTLI_SqL"
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
urn:ietf:params:oauth:ckt:sha-256:-fMDrirSTd4f89-yghaFu9KC0ovpCQFpUCThB2OyKCg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'356c5a36...4c7a3259',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'015c60b5...b05edafb',       / x public key component        /
  -3: h'01f00374...4358780a',       / y public key component        /
  -4: h'01a757bd...9655769f',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:5lZ6atVornFTZWVNBEKUoAagwXwm8w0jNe2twyCLz2Y
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "5lZ6atVornFTZWVNBEKUoAagwXwm8w0jNe2twyCLz2Y",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AVxgtRjO702Uc6etfKD3bqVkcEaUOGmOll9l0x0lMnf7vfZX12fR7h9SwjbBE2LxEGikG6JCJBE-RRFNVfqwXtr7",
  "y": "AfADdAJkm0PHtWizyKxfQJqJ8T5gUT9IVa1rpw6jtHS_VTOaVVEtezqRgVFX1x9bzEoK37fTvROGmavI8EpDWHgK",
  "d": "AadXvQSxFDrr8nIc8JZDkyxpIVN9tMuTAP8n6QsjXi6dXDD8bzILqESAREZhaAFwrN_y6Fz6tQDmf_FskKCWVXaf"
}
~~~~