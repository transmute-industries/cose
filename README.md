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

🔥 This package is not stable or suitable for production use 🚧

```bash
npm install '@transmute/cose'
```

```js
const cose = require("@transmute/cose");
```

```ts
import * as cose from "@transmute/cose";

const private_key = await cose.crypto.key.generate<
  "ES256",
  "application/jwk+json"
>({
  type: "application/jwk+json",
  algorithm: "ES256",
});

const public_key = cose.public_from_private({
  key: private_key,
  type: "application/jwk+json",
});

// see tests for current APIs
```

### Transparency

```edn
/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "vCl7UcS0ZZY99VpRthDc-0iUjLdfLtnmFqLJ2-Tt8N4",
    / algorithm / 1 : -7,  # ES256
    / hash  / -6800 : -16, # SHA-256
    / content  / -6802 : "application/spdx+json",
    / location / -6801 : "https://cloud.example/sbom/42",
    / claims / 15 : {
      / issuer  / 1 : "https://green.example",
      / subject / 2 : "https://green.example/cli@v1.2.3",
    },
  }>>,
  / unprotected / {
    / receipts / 394 : {
      <</ cose-sign1 / 18([
        / protected   / <<{
          / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
          / algorithm / 1 : -7,  # ES256
          / notary    / 395 : 1, # RFC9162 SHA-256
          / claims / 15 : {
            / issuer  / 1 : "https://blue.example",
            / subject / 2 : "https://green.example/cli@v1.2.3",
          },
        }>>,
        / unprotected / {
          / proofs / 396 : {
            / inclusion / -1 : [
              <<[
                / size / 9, / leaf / 8,
                / inclusion path /
                h'7558a95f...e02e35d6'
              ]>>
            ],
          },
        },
        / payload     / null,
        / signature   / h'02d227ed...ccd3774f'
      ])>>,
      <</ cose-sign1 / 18([
        / protected   / <<{
          / key / 4 : "ajOkeBTJou_wPrlExLMw7L9OTCD5ZIOBYc-O6LESe9c",
          / algorithm / 1 : -7,  # ES256
          / notary    / 395 : 1, # RFC9162 SHA-256
          / claims / 15 : {
            / issuer  / 1 : "https://orange.example",
            / subject / 2 : "https://green.example/cli@v1.2.3",
          },
        }>>,
        / unprotected / {
          / proofs / 396 : {
            / inclusion / -1 : [
              <<[
                / size / 6, / leaf / 5,
                / inclusion path /
                h'9352f974...4ffa7ce0',
                h'54806f32...f007ea06'
              ]>>
            ],
          },
        },
        / payload     / null,
        / signature   / h'36581f38...a5581960'
      ])>>
    },
  },
  / payload     / h'0167c57c...deeed6d4',
  / signature   / h'2544f2ed...5840893b'
])

```

### COSE RFCs

- [RFC9360 - Header Parameters for Carrying and Referencing X.509 Certificates](https://datatracker.ietf.org/doc/rfc9360/)
- [RFC9052 - Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC9053 - Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)

### COSE Drafts

- [COSE Receipts](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- [COSE Hash Envelope](https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/)
- [COSE HPKE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)

### SCITT Drafts

- [SCITT Architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
