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
urn:ietf:params:oauth:ckt:sha-256:-G2I_xiD-dDFWAgdt9mqTUu20KNucfQ-tRCK-MEuyHw
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'4b423374...30426330',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'f4a08f66...01f403b4',       / x public key component        /
  -3: h'96293167...648324eb',       / y public key component        /
  -4: h'3ee926c9...2678359c',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:KB3t8ZjJjNH5Gw4bxkcH6L9QRaY_vBmT94C7utb0Bc0
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "KB3t8ZjJjNH5Gw4bxkcH6L9QRaY_vBmT94C7utb0Bc0",
  "alg": "ES256",
  "crv": "P-256",
  "x": "9KCPZlAzFLOYUsqkT2HYPJ4nQOqCJPgI5AMvKwH0A7Q",
  "y": "likxZ8tvt-c6CB72ZlhEEQ1sPt6BaNi0qammsWSDJOs",
  "d": "PukmydTAybH5OTuKS7LN3qcDmAN8PwKMrI77WSZ4NZw"
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
urn:ietf:params:oauth:ckt:sha-256:2dg9t_Qymx8qPihWUKhjFpQJMozaY9sBdnBq-XcFlKs
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'57706770...34773159',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'893b29c8...4edd3d70',       / x public key component        /
  -3: h'95c2db9d...48b7753c',       / y public key component        /
  -4: h'3d3bc697...28706c1b',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:WpgpiZnO2YgZpjIvRf2Qob04-sPgS1nHNC5Qy1h4w1Y
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "WpgpiZnO2YgZpjIvRf2Qob04-sPgS1nHNC5Qy1h4w1Y",
  "alg": "ES384",
  "crv": "P-384",
  "x": "iTspyG327yRpgr2t-4XdYLiWGWPn0sohwNAFk0Fg_6y6jf2nDZu1A-YD5kVO3T1w",
  "y": "lcLbndZxDWCK7ExGjEnjq7q27Rgd2ePs_mwxJcDumsBM9AMe-bYA1vX16aBIt3U8",
  "d": "PTvGl8BYmro8K8KZyB6_ByQdnb2Tbg-0ge_0JGmg2d6hb4CxDa3Zn0aM7ogocGwb"
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
urn:ietf:params:oauth:ckt:sha-256:0tDCaw_GhKkzZT2RP10Di3aB9BoodWz6Q1F-VBenMgE
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'41426650...4547386f',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'00399c78...6b9c4eb1',       / x public key component        /
  -3: h'0095f9bb...1820db15',       / y public key component        /
  -4: h'011dc8dc...175b512f',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:ABfPuUEsj92Bxkvo9v-ifHoEULq_8hoNsBFwPt-EG8o
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "ABfPuUEsj92Bxkvo9v-ifHoEULq_8hoNsBFwPt-EG8o",
  "alg": "ES512",
  "crv": "P-521",
  "x": "ADmceBMwHr5wZtGR-xNmqIoMgyfTy0CVTBA8vyKKIvw9ADHnwMBc2ltfUVCUzSh6GaSNBkmOUeSCiGi3iAprnE6x",
  "y": "AJX5uwLDS7D5O3aDnA51pfGnQq5wG6SAI5Pyz-OfBbiU5uggRViqTI-N_DXphtqZKBdwNnzIjZdXwjaRcrsYINsV",
  "d": "AR3I3MkG6JhzNXnDG7TOV66CNP_ZX8Gf1xfK0ATGoA1WxYruc94B6os8YZh_1NIBYwpOhaIkFQWbPbVFmd0XW1Ev"
}
~~~~