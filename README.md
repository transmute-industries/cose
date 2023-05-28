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

```ts
import cose from '@transmute/cose'

const entries: Uint8Array[] = []
for (let i = 0; i < 10; i++) {
  entries.push(cose.strToBin(`${String.fromCharCode(65 + i)}`))
}
const root = cose.treeHead(entries)
const inclusionProof = cose.inclusionProof(entries[2], entries)
const leaf = cose.leaf(entries[2])
const verifiedInclusionProof = cose.verifyInclusionProof(
  root,
  leaf,
  inclusionProof,
)
// expect(verifiedInclusionProof).toBe(true)
entries.push(cose.strToBin('Spicy update 🔥'))
const root2 = cose.treeHead(entries)
const consistencyProof = cose.consistencyProof(inclusionProof, entries)
const verifiedConsistencyProof = cose.verifyConsistencyProof(
  root,
  root2,
  consistencyProof,
)
// expect(verifiedConsistencyProof).toBe(true)
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
