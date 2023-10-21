## ES256

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:5ivaEgH2IYHu_ZMsvax0wcNPMxIuufNHM85rqc0PPFw
~~~~

~~~~ cbor-diag
{                                   / COSE Key                              /
  1: 2,                             / Type                                  /
  2: h'36334330...5f4c7649',        / Identifier                            /
  3: -7,                            / Algorithm                             /
  -1: 1,                            / Curve                                 /
  -2: h'594d8284...685ec307',       / x public key component                /
  -3: h'44b876c9...4d7806ed',       / y public key component                /
  -4: h'a80385df...66eb0c4f',       / d private key component               /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:63C0C0u_Z46VA41L2z4GOWEDzfig_Lkwkz1St4J_LvI
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "63C0C0u_Z46VA41L2z4GOWEDzfig_Lkwkz1St4J_LvI",
  "alg": "ES256",
  "crv": "P-256",
  "x": "WU2ChLuJqQLfYajEB4ZTN_GDvPGmssG0xtK_7Ghewwc",
  "y": "RLh2ydG2hTcTSvo5FDOd39s7EcD2_BUE1-QtU014Bu0",
  "d": "qAOF38BMZ1EoL0muyi0o9H5B97rVAl6MOoBVu2brDE8"
}
~~~~

## ES384

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:BsR7j42mmQxHYmN8djczUUZo5VvZ39PnnuKXrths0y8
~~~~

~~~~ cbor-diag
{                                   / COSE Key                              /
  1: 2,                             / Type                                  /
  2: h'6d314655...37414e49',        / Identifier                            /
  3: -35,                           / Algorithm                             /
  -1: 2,                            / Curve                                 /
  -2: h'ab6367bd...1314b0c8',       / x public key component                /
  -3: h'b49efa18...86d33a38',       / y public key component                /
  -4: h'8166db3d...4ed6c4f0',       / d private key component               /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:m1FUWiFYhct0N9OcqoItfvGOX4hwxngn0c_UUNd7ANI
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "m1FUWiFYhct0N9OcqoItfvGOX4hwxngn0c_UUNd7ANI",
  "alg": "ES384",
  "crv": "P-384",
  "x": "q2NnveHKmPJtCMmq0Iob_WECXzOhU46GCSjLz40bFJLqyfo3PnLXDU6IzWATFLDI",
  "y": "tJ76GK3jPDRHYfTwQciiHjCdd5SOmzxRTmfuHwLM5DJF505t4s9y_ZpEaUGG0zo4",
  "d": "gWbbPQA-C6ojqt_tm02O40XfkXS3ApU1FY_nltHoOKcit9C4JzifCzm9cglO1sTw"
}
~~~~

## ES512

### EDN

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:Uu8Ovi_3NylAflySCTG8FwK4vDhoKxzqqrFCilqfwfU
~~~~

~~~~ cbor-diag
{                                   / COSE Key                              /
  1: 2,                             / Type                                  /
  2: h'50756757...51334277',        / Identifier                            /
  3: -36,                           / Algorithm                             /
  -1: 3,                            / Curve                                 /
  -2: h'01587b77...48731f8f',       / x public key component                /
  -3: h'0105c662...102d2dc0',       / y public key component                /
  -4: h'00f000cb...7f0ae3a1',       / d private key component               /
}
~~~~

### JSON

~~~~ text
urn:ietf:params:oauth:jwk-thumbprint:sha-256:PugWqSXv7LY5KbXUCI2mSRfP6S4DBtHkHHPWNZdQ3Bw
~~~~

~~~~ json
{
  "kty": "EC",
  "kid": "PugWqSXv7LY5KbXUCI2mSRfP6S4DBtHkHHPWNZdQ3Bw",
  "alg": "ES512",
  "crv": "P-521",
  "x": "AVh7d-Aui7eHzrWkmRrHEwdrUbZstxExFRklCasDem5m52NZ9i3metqrJHjmH5hIICKpg9q7KaYo-4glKeJIcx-P",
  "y": "AQXGYsfiDKT85idL7wyqvWHhj0LGhhAyhaDKKbuSzkCoEEdCJnjqtEs_VJf7X6AHlZWpu6QWKsMQnc-1oY4QLS3A",
  "d": "APAAy26tXQEQR4yFoVNIm4Ctjjx2efNOzHkOdk0QHZ7fd1gUD-j_anJpkR8uqIE8mkqzqBKwspKyrJ3JKuZ_CuOh"
}
~~~~