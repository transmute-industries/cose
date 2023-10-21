``` ts
import cose from '@transmute/cose'
```

## Generate Private Key

``` ts
const secretCoseKey = await cose.key.generate(-7)
const thumbprintOfSecretKey = await cose.key.thumbprint.uri(secretCoseKey)
const diagnosticOfSecretKey = await cose.key.edn(secretCoseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:ge1J2C2lSCxoD1tEO8d_wz8xmbOO1o17Uf89O-VcaCg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'674e7271...32463159',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'cece1563...3344952f',       / x public key component        /
  -3: h'289c8200...63000d31',       / y public key component        /
  -4: h'3d5fcfe3...f43d31f0',       / d private key component       /
}
~~~~

## Export Public Key

``` ts
const publicKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicKey)
const diagnosticOfPublicKey = await cose.key.edn(publicKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:ge1J2C2lSCxoD1tEO8d_wz8xmbOO1o17Uf89O-VcaCg
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'674e7271...32463159',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'cece1563...3344952f',       / x public key component        /
  -3: h'289c8200...63000d31',       / y public key component        /
}
~~~~