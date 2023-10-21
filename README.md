# cose

[![CI](https://github.com/transmute-industries/cose/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/cose/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@transmute/cose.png?mini=true)](https://npmjs.org/package/@transmute/cose) -->

<img src="./transmute-banner.png" />

#### [Questions? Contact Transmute](https://transmute.typeform.com/to/RshfIw?typeform-source=cose)

## Usage

```bash
npm install '@transmute/cose'
```

```ts
import cose from '@transmute/cose'
```

```js
const cose = require('@transmute/cose')
```

### Inclusion Proof

```ts
const signed_inclusion_proof = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: log_id,
    leaf_index: 2,
    leaves,
    signer,
  })
```

~~~~ cbor-diag
18(                                 / COSE Single Signer Data Object        /
    [
      h'a2012604...6d706c65',       / Protected header                      /
      {                             / Unprotected header                    /
        100: [                      / Inclusion proofs (2)                  /
          h'83040282...1f487bb1',   / Inclusion proof 1                     /
          h'83040382...1f487bb1',   / Inclusion proof 2                     /
        ]
      },
      h'',                          / Payload                               /
      h'efde9a59...b4cb142b'        / Signature                             /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected header                      /
  1: -7,                            / Cryptographic algorithm to use        /
  4: h'68747470...6d706c65'         / Key identifier                        /
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1                     /
  4,                                / Tree size                             /
  2,                                / Leaf index                            /
  [                                 / Inclusion hashes (2)                  /
     h'a39655d4...d29a968a'         / Intermediate hash 1                   /
     h'57187dff...1f487bb1'         / Intermediate hash 2                   /
  ]
]
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 2                     /
  4,                                / Tree size                             /
  3,                                / Leaf index                            /
  [                                 / Inclusion hashes (2)                  /
     h'e7f16481...aab81688'         / Intermediate hash 1                   /
     h'57187dff...1f487bb1'         / Intermediate hash 2                   /
  ]
]
~~~~

See also :

- [RFC9162](https://datatracker.ietf.org/doc/rfc9162/).
- [draft-steele-cose-merkle-tree-proofs](https://github.com/ietf-scitt/draft-steele-cose-merkle-tree-proofs).

#### Setup

```ts
import cose from '@transmute/cose'
const signer = await cose.signer({
  privateKeyJwk: {
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    d: 'o_95vWSheg19YU7viU3PmW_kRIWk14HiVLXDXiZjEL0',
    x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
    y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
  },
})
const verifier = await cose.verifier({
  publicKeyJwk: {
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
    y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
  },
})
```

#### Issue Inclusion Proof

```ts
const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })

const entries = [message0, message1, message2, message3]
const leaves = entries.map(cose.merkle.leaf)
const old_root = await cose.merkle.root({ leaves })

const signed_inclusion_proof = await cose.merkle.inclusion_proof({
  leaf_index: 2,
  leaves,
  signer,
})
```

#### Verify Inclusion Proof

```ts
const verified_inclusion_proof = await cose.merkle.verify_inclusion_proof({
  leaf: cose.merkle.leaf(entries[2]),
  signed_inclusion_proof,
  verifier,
})
```

#### Multi Verify

```ts
const verified3 = await cose.merkle.verify_multiple(
  {
    leaves: [cose.merkle.leaf(entries[2]), cose.merkle.leaf(entries[3])],
    signed_inclusion_proof: updated,
    verifier
  }
)
```

#### Issue Consistency Proof

```ts
const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
const leaves2 = entries.map(cose.merkle.leaf)
const signed_consistency_proof = await cose.merkle.consistency_proof({
  signed_inclusion_proof,
  leaves: leaves2,
  signer,
})
```

#### Verify Consistency Proof

```ts
const verified = await cose.merkle.verify_consistency_proof({
  old_root,
  signed_consistency_proof,
  verifier,
})
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
