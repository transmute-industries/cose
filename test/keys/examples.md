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
urn:ietf:params:oauth:ckt:sha-256:LfT31C7TjQxIfiY2-HBZRt9Vpm4RizHPFfX9WukUA68
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'37726d6c...724d7255',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'bfdc8460...acb49f30',       / x public key component        /
  -3: h'4b29ce16...21d97546',       / y public key component        /
  -4: h'eed1c146...03b8bfe1',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:7rml42ImGRnpLmwOyC08lqBVtSM3bR0zLMv8iSIrMrU
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "7rml42ImGRnpLmwOyC08lqBVtSM3bR0zLMv8iSIrMrU",
  "alg": "ES256",
  "crv": "P-256",
  "x": "v9yEYDiCUkT4hxtIRdnc8Og6yU0X2CUWilA4May0nzA",
  "y": "SynOFhZYP4_jxvMheSzVIiGEsHCrXZ-lKIHbjCHZdUY",
  "d": "7tHBRpC58IwMT7z3L4ljQdIEceEU0db6StuTgAO4v-E"
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
urn:ietf:params:oauth:ckt:sha-256:hjt5-k7---fRyWjsbOhy0SDzzFAGQi_Ye7q8maoA-_E
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'684b6d42...4b52496f',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'3f91fef3...e935d265',       / x public key component        /
  -3: h'5559c4b6...1158d2b7',       / y public key component        /
  -4: h'b6eefefa...6a885bc1',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:hKmBQWM9yd2R17Vo5Q86RD5foasE4Fa84r4hUtGKRIo
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "hKmBQWM9yd2R17Vo5Q86RD5foasE4Fa84r4hUtGKRIo",
  "alg": "ES384",
  "crv": "P-384",
  "x": "P5H-8x89uj-PRB7CjAuK5KtHMRK5zSZMZj7Juzetdi46asGNJ28Jm9uQD-bpNdJl",
  "y": "VVnEtu4EpAG0okh649SWwou9jGNN1dqlLKiK9_63U8FQARRqGxPU9Egd3rkRWNK3",
  "d": "tu7--gihpkavYlT0x4TVKrpKuDB_bydnK4XZ-v6Uhz19shXXIFJSkE5YS3BqiFvB"
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
urn:ietf:params:oauth:ckt:sha-256:-YPcMUOiI1QFj2UnFxwHieOUoYKPHvpehc9AfYY_-RI
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6c52537a...79364a45',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'00b7deca...54f118c9',       / x public key component        /
  -3: h'01f48fe5...117a5f80',       / y public key component        /
  -4: h'012afa22...f4f5df4c',       / d private key component       /
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
urn:ietf:params:oauth:jwk-thumbprint:sha-256:lRSzQpQ5Hw55--61RzFxjfiFHUmi5waWdQonILCy6JE
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "lRSzQpQ5Hw55--61RzFxjfiFHUmi5waWdQonILCy6JE",
  "alg": "ES512",
  "crv": "P-521",
  "x": "ALfeyi3A4sjboAnPxleoS8W33eKjekZ_XjFdYIucAzvPLA_fFpf8E3uP3FggmFI9nci7-N8wnrgfPklol2RU8RjJ",
  "y": "AfSP5SJnojyr72-8tvxHa3sLGoTmrPRu1v5-Va72xV3FXDq_MmpsJXnbDVSov1ZR_SB-jzFargejt9YxRcgRel-A",
  "d": "ASr6Iudu0L_hn5VOfDiwGiRagrsJ1cYtMkmUltlNHcD8-_MRks0BWOS4LrFnrT4yKcQtsEUY7WQa6LvlsCL09d9M"
}
~~~~