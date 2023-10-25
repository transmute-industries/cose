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
urn:ietf:params:oauth:ckt:sha-256:PnldLD3BQIUi-JyRseUvsmcORHj2nAREgiv1sWpWF_U
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4a504f69...50484f77',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'ca202cae...2b487092',       / x public key component        /
  -3: h'aeb1539f...e573eed5',       / y public key component        /
  -4: h'99a36a67...24a3798f',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:JPOiEwx-3LRWkByPgYpQY0xGIqNtizBtuWfq0gkPHOw
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "JPOiEwx-3LRWkByPgYpQY0xGIqNtizBtuWfq0gkPHOw",
  "alg": "ES256",
  "crv": "P-256",
  "x": "yiAsrvtxpHc1GHFkxO5XtpWPuND_37iJ7VpHHytIcJI",
  "y": "rrFTn4lvfUg3fzMbycqOqNwEO1mIiE8i-xGKAeVz7tU",
  "d": "maNqZ5cYj42ZEcsw40hpohiOM3i_6Ih4qa3arSSjeY8"
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
urn:ietf:params:oauth:ckt:sha-256:nYbjCdujrqII9t-BcWSIRE2HHN5Y8pu8zjRy9wGptwA
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'33467368...3755356f',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'98c3bbed...7537a2b6',       / x public key component        /
  -3: h'8f781966...11cedcc1',       / y public key component        /
  -4: h'e101a107...cdee622e',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:3FshpXKTFch6YYyEisQb0GbeW-JCR2TwM7q7myw7U5o
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "3FshpXKTFch6YYyEisQb0GbeW-JCR2TwM7q7myw7U5o",
  "alg": "ES384",
  "crv": "P-384",
  "x": "mMO77Qhtb-tfHlS9eCqF2_Vh5avL3k64pNN5v_YwxqFkmA5Mr2RSHl0LYsZ1N6K2",
  "y": "j3gZZgbPwJkKmLI9PgFkNjbC9MyWbR9-xgsk74a_8KZ_CI5SVacm8PAISqIRztzB",
  "d": "4QGhB2L-NE6-3PXmb-gy5N7stShXkPl_pR6grKSme3nu2pHQKkV5z7_OQUrN7mIu"
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
urn:ietf:params:oauth:ckt:sha-256:su2iN5B4FSLNR2OErHjmpblqmrJvcBle2iYbzgYskxk
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4a534964...38563363',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'019ccba0...bbe16600',       / x public key component        /
  -3: h'00a0d2d3...0350b76e',       / y public key component        /
  -4: h'011f9ef7...55c80401',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:JSIdOCbqyPGvRDwMDlX10llYwvsi_T6erBcc2t98V3c
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "JSIdOCbqyPGvRDwMDlX10llYwvsi_T6erBcc2t98V3c",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AZzLoLVpm1TUMqlivTYlHwYQ97qb5d3jVC63ZK8n03NKnOr9hCRP9fl4Fqi8DpyCdXtgu2-Cw2OImg5SYWa74WYA",
  "y": "AKDS05ThDwScdB9fZ-vpV-L8yT7iZMAPBd1b5Bwebm3mnhp4G2Hk5ZxAfyoJG_vJ5exED-so8mw-T17d_WoDULdu",
  "d": "AR-e97SM2nvvNxcoebfxeC3GGfqBl6zNk6lZIHubh4eYYQA__Dzeal3ZW66fp_ZuLUESn2qnO666fgfUqthVyAQB"
}
~~~~