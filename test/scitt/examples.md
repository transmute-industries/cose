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
urn:ietf:params:oauth:ckt:sha-256:ZIG6-_JGh2i-HIOtconNfCp3vQxbTNxiyfWHgOid00o
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'45513539...4d77336f',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'7e557c8c...3dbc7872',       / x public key component        /
  -3: h'87bda927...e7878b90',       / y public key component        /
  -4: h'93c4d3c3...a0e3c560',       / d private key component       /
}
~~~~

## Export Public Key

``` ts
const publicCoseKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicCoseKey)
const diagnosticOfPublicKey = await cose.key.edn(publicCoseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:ZIG6-_JGh2i-HIOtconNfCp3vQxbTNxiyfWHgOid00o
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'45513539...4d77336f',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'7e557c8c...3dbc7872',       / x public key component        /
  -3: h'87bda927...e7878b90',       / y public key component        /
}
~~~~

## Issue Receipt

``` ts
const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })
const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
const entries = [message0, message1, message2, message3, message4, message5]
const receipt = await cose.scitt.receipt.issue({
  index: 4,
  entries: entries,
  secretCoseKey
})
const diagnostic = await cose.scitt.receipt.edn(receipt)
```

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a3012604...392b6601',       / Protected                     /
      {                             / Unprotected                   /
        -22222: {                   / Proofs                        /
          1: [                      / Inclusion proofs (1)          /
            h'83060482...32568964', / Inclusion proof 1             /
          ]
        },
      },
      nil,                          / Detached payload              /
      h'309deccf...9dd16b07'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: "EQ59hwO88t5yDwM34frVW9OlaRa7s3coPaN8SWKMw3o",/ Key identifier /
  -11111: 1                         / Verifiable data structure     /
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  6,                                / Tree size                     /
  4,                                / Leaf index                    /
  [                                 / Inclusion hashes (2)          /
     h'aa1a3c19...15a276cc'         / Intermediate hash 1           /
     h'0bdaaed3...32568964'         / Intermediate hash 2           /
  ]
]
~~~~

## Verify Receipt

``` ts
const verificaton = await cose.scitt.receipt.verify({
  entry: entries[4],
  receipt,
  publicCoseKey
})
console.log({ verificaton })
```


~~~~ text
{ verificaton: true }
~~~~