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
urn:ietf:params:oauth:ckt:sha-256:znFTVwJYhrooFNbHO4_fEc6_tu13h7j0YQjjtHyRRn0
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'425a6161...4a43314d',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'f1dde7cd...550ac610',       / x public key component        /
  -3: h'a98e9c84...a6f424c1',       / y public key component        /
  -4: h'bf686a56...d112fbaf',       / d private key component       /
}
~~~~

## Export Public Key

``` ts
const publicKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicKey)
const diagnosticOfPublicKey = await cose.key.edn(publicKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:znFTVwJYhrooFNbHO4_fEc6_tu13h7j0YQjjtHyRRn0
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'425a6161...4a43314d',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'f1dde7cd...550ac610',       / x public key component        /
  -3: h'a98e9c84...a6f424c1',       / y public key component        /
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
      h'',                          / Detached payload              /
      h'97343991...a4265c61'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'425a6161...4a43314d',        / Key identifier                /
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