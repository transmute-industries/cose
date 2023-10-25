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
urn:ietf:params:oauth:ckt:sha-256:SptMWs4m45TGJ1i9t4u9wFhNsZmK9xedJ0v3RiM7hBo
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'73704d62...412d6859',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'7889dc58...d334079d',       / x public key component        /
  -3: h'adcec898...009dd349',       / y public key component        /
  -4: h'3832bd30...e58bb9b0',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:spMbGqIE8Xs51QWdN-Ex5r6jzPMzmyYY_kMfC-RA-hY
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "spMbGqIE8Xs51QWdN-Ex5r6jzPMzmyYY_kMfC-RA-hY",
  "alg": "ES256",
  "crv": "P-256",
  "x": "eIncWAqHgepHxDDXYYpIhvI_BBOipF5UEWUk7dM0B50",
  "y": "rc7ImAyZx9Y_YJtywzVBqHjiyzAWwjUG7smGxACd00k",
  "d": "ODK9MCqzBmFhYdaL2H418gJST_vZdPF8qCzpXuWLubA"
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
urn:ietf:params:oauth:ckt:sha-256:ri5GZ7JNdmH6i2B7nWAuNUzKhljiY6hsgsfIwsq9mUM
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'377a476a...7655766f',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'2fb8706a...558fe489',       / x public key component        /
  -3: h'f9f7eed5...03350524',       / y public key component        /
  -4: h'6a095168...6d651cfe',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:7zGj3AZkTI3UVV4Qne9owotlheBJ0Qorq9WWO8CvUvo
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "7zGj3AZkTI3UVV4Qne9owotlheBJ0Qorq9WWO8CvUvo",
  "alg": "ES384",
  "crv": "P-384",
  "x": "L7hwarbbyJd2iUYd1Qxor3FwG_hL5qqQEiQ1p7I-Hcyp-uQgkJfw7rSTDHtVj-SJ",
  "y": "-ffu1Qx1SazG6LOZ0CLdXVu6nmOEN9FnQ9J7iSkYOxFZMU2_7aydfOPcbE0DNQUk",
  "d": "aglRaDMkR_x0p5Pdb5kujh4dJ9sQM5W03vTO-wVvquyJYxtRtITIL-70pjdtZRz-"
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
urn:ietf:params:oauth:ckt:sha-256:Yj1z6X-4vv8_eFQWYRlkL3dQRyoi8_8sLUFxvbfbv7M
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6e31434c...6b366641',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'00436af0...913cdb95',       / x public key component        /
  -3: h'01ef4450...3180cce0',       / y public key component        /
  -4: h'00876275...33f3a21a',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:n1CLEz6zEoSunWVqDTde_FtjclIQ5EYxf17x4cok6fA
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "n1CLEz6zEoSunWVqDTde_FtjclIQ5EYxf17x4cok6fA",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AENq8HSmnxYUce4Bh4v4sxxRx04BqeF-rTZaQKHXUKdCmIzHbI2lJWuzY-cmKrAOkNbNkvTQb-6lQdPljoqRPNuV",
  "y": "Ae9EUEVVo3kyQ5sklBwvgdTeqlzB2PtGzJCN7fp_jjMOQNpLDpsOjpoSJMl1Blo0FT1r6nLTRnNRDUXfUuUxgMzg",
  "d": "AIdiddpaGyi06qzGJYwXr3e3QVnVyV1Y-EqVURECAIxL85kVxaigTpythIsBfKPgtGr3lyD3HxNxVpYX35cz86Ia"
}
~~~~