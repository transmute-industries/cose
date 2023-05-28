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

### Usage

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
