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
urn:ietf:params:oauth:ckt:sha-256:gIpbKy9TPvcudjF_O2d57IBjQ5c2xwbRFjyHjTZLfbo
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6676746a...3272796f',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'b571b251...e0e6152f',       / x public key component        /
  -3: h'f3013d23...8dc7076e',       / y public key component        /
  -4: h'21bf0101...5d57358a',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:fvtjWuZZQTCH6tDp299l89pTsfSCp_LvjsxYcAs2ryo
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "fvtjWuZZQTCH6tDp299l89pTsfSCp_LvjsxYcAs2ryo",
  "alg": "ES256",
  "crv": "P-256",
  "x": "tXGyURDVk_5yhSTcAbBlCMnkrOXeQgJUPA6DueDmFS8",
  "y": "8wE9IyjJlxoh8Da64qt6rwjCsZ_EUxXiCOEWK43HB24",
  "d": "Ib8BAYcd89LlocunapksSV8fY_4R1IXX0MxROV1XNYo"
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
urn:ietf:params:oauth:ckt:sha-256:BGYaz3F3BJglctQLvqyo8Kug7rJ8lhEdMLly_YqAYGk
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'35786a76...6d473551',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'f1a803f9...9c33a14c',       / x public key component        /
  -3: h'0f0ac52d...ffac776f',       / y public key component        /
  -4: h'3766af40...b67a848a',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:5xjvZ2BAjZJWiwJgXmTofVGS3DfZH8RPZ9Wb_SimG5Q
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "5xjvZ2BAjZJWiwJgXmTofVGS3DfZH8RPZ9Wb_SimG5Q",
  "alg": "ES384",
  "crv": "P-384",
  "x": "8agD-RebXzpn9MXdNV0yk-DhKezysLeHURDjSzGNQFWnITp_SS3LB8NngQ2cM6FM",
  "y": "DwrFLRHHdpkbWBVxKhS_IYHFbqh8mKhnKeEg_doZBX5jNsPKk62wnyEqlbj_rHdv",
  "d": "N2avQJ6zSS3UvC16W1lHKbtmicBzDwbW_8h5I7xJaXnk5a4AFvFR2-XQXX22eoSK"
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
urn:ietf:params:oauth:ckt:sha-256:C-fkWW_UK1xCQXmHtRT5lPmHV0Mqil2vxWUYtxbcF1c
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'58794853...57597345',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'0087672d...33f4205b',       / x public key component        /
  -3: h'00de55fb...667b311b',       / y public key component        /
  -4: h'015677d9...9db29640',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:XyHSTf-qB5Ob14GKdXL2giDEgkmecvlrrRaA7FuWYsE
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "XyHSTf-qB5Ob14GKdXL2giDEgkmecvlrrRaA7FuWYsE",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AIdnLds9QCTRDqG4AB4WGWThslmNbTXrj1QU12FnMBPUDzJOfK9PvHqMk5q8ZWXC9F8Iv9YkeRSkDZuxW-0z9CBb",
  "y": "AN5V-w_81z9v7pClD9DnbK7ELWi_Np_Sr4c1p1PsRVLgYyNB_YkTKr1Q0BUwlWoXeSecU729VF1OR8sLK4tmezEb",
  "d": "AVZ32b-ooHoYZ1oBdwu2yDWsIkXbEK-nkdnLrPQobXCyNDjyjlBMJnfyUvqdmev6oZ_kAEl5QPNoTQshBlmdspZA"
}
~~~~