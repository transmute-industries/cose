## ES256

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:OYx_pjWTE1bqFFin039CI-Zd0u_CSfelnVTdAWLcZOA
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'774f734c...664f4445',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'b11a7946...467a61b8',       / x public key component        /
  -3: h'c28ee365...ef7b0de7',       / y public key component        /
  -4: h'2936dea5...a51ffd24',       / d private key component       /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:wOsLudfdvand2xc271kA-ekMNN6GMAdSQnS67SgfODE
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "wOsLudfdvand2xc271kA-ekMNN6GMAdSQnS67SgfODE",
  "alg": "ES256",
  "crv": "P-256",
  "x": "sRp5RtsBoEMSxSzxCJXAspOSLLFpJkbIsM0NuEZ6Ybg",
  "y": "wo7jZYh45YiaUazummSpS1Hlnp5jA7W1vSgUp-97Dec",
  "d": "KTbepRQURfh2GT5azQWyvK315tOf1Nnx7huV-qUf_SQ"
}
~~~~

## ES384

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:onklmpRsKD5vpF3dz5KdLv9ixZrlYi9UXO9iDJ8Ywqc
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6b344849...6e37506b',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'165ccd35...7ce463b4',       / x public key component        /
  -3: h'f5670d59...d503a3a6',       / y public key component        /
  -4: h'19cf992e...26bb8670',       / d private key component       /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:k4HI4zaThxGjDMxIQ1UnCySlC3OU58Y_e8V5fjOn7Pk
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "k4HI4zaThxGjDMxIQ1UnCySlC3OU58Y_e8V5fjOn7Pk",
  "alg": "ES384",
  "crv": "P-384",
  "x": "FlzNNe0QGFtcldFqIy2cH7s3_upx4QtjS3DAxhD1p0H4QDnEwPSxDHVDqh585GO0",
  "y": "9WcNWYKzYOSvypdtU6dyP5WmuVA43ITAYiVU75xexaC0VyNXBL6RBk_2Ve_VA6Om",
  "d": "Gc-ZLuOBvTj6Ov-z5T4N52eqNX-0Pxy4iBL_eIUYvP1aYkwtLbX1xjfpbgsmu4Zw"
}
~~~~

## ES512

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:kwzn3nFYPEvUHBA_fdeh1sgtPhzGoYbsO5YALYiJmHU
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'317a7955...57337777',        / Identifier                    /
  3: -36,                           / Algorithm                     /
  -1: 3,                            / Curve                         /
  -2: h'0117caca...7f221089',       / x public key component        /
  -3: h'01e996eb...5fef632b',       / y public key component        /
  -4: h'00092ee4...52fe6190',       / d private key component       /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:1zyUhPbZ4A4AhDsGKef_PwunBr2kgsHgYE7LpRCW3ww
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "1zyUhPbZ4A4AhDsGKef_PwunBr2kgsHgYE7LpRCW3ww",
  "alg": "ES512",
  "crv": "P-521",
  "x": "ARfKyhdnV3kJ1OW1Yx1503x0yL-0XAZebws-7Gs-yqipSK-BzhWY15mX_U8Qm3ronZ8_YZKJoAZ4MAuzvEx_IhCJ",
  "y": "AemW66TUPTcYDQSOdFWPXm3mPi45_khLpGQyUNyKXeDigPZ1PzL9K11VwLYHZSzSjz5o1a2ci5jdRrjc7qtf72Mr",
  "d": "AAku5JS6U9Y3-Iw4fn3CcQGRtrJ4o2LvRRQDqCA4MhyWW1S6-g_UOWNzaahKJswBK5OYP5XikFv8IfY7sy9S_mGQ"
}
~~~~