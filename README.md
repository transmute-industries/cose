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

```ts
import * as cose from "@transmute/cose";
```

```js
const cose = require("@transmute/cose");
```

```ts
const issuerSecretKeyJwk = await cose.key.generate<cose.SecretKeyJwk>(
  "ES256",
  "application/jwk+json"
);
const issuerPublicKeyJwk = await cose.key.publicFromPrivate<cose.PublicKeyJwk>(
  issuerSecretKeyJwk
);

const notarySecretKeyJwk = await cose.key.generate<cose.SecretKeyJwk>(
  "ES256",
  "application/jwk+json"
);
const notaryPublicKeyJwk = await cose.key.publicFromPrivate<cose.PublicKeyJwk>(
  notarySecretKeyJwk
);
const issuer = cose.detached.signer({ secretKeyJwk: issuerSecretKeyJwk });
const notary = cose.detached.signer({ secretKeyJwk: notarySecretKeyJwk });

const content = fs.readFileSync("./examples/image.png");
const signatureForImage = await issuer.sign({
  protectedHeader: new Map<number, any>([
    [1, -7], // signing algorithm ES256
    [3, "image/png"], // content type image/png
    [4, issuerPublicKeyJwk.kid], // issuer key identifier
  ]),
  unprotectedHeader: new Map(),
  payload: content,
});
const transparencyLogContainingImageSignatures = [
  await cose.receipt.leaf(signatureForImage),
];
const receiptForImageSignature = await cose.receipt.inclusion.issue({
  protectedHeader: new Map<number, any>([
    [1, -7], // signing algorithm ES256
    [-111, 1], // inclusion proof from RFC9162
    [4, notaryPublicKeyJwk.kid], // notary key identifier
  ]),
  entry: 0,
  entries: transparencyLogContainingImageSignatures,
  signer: notary,
});
const transparentSignature = await cose.receipt.add(
  signatureForImage,
  receiptForImageSignature
);
const resolve = async (
  header: cose.ProtectedHeaderMap
): Promise<cose.PublicKeyJwk> => {
  const kid = header.get(4);
  if (kid === issuerPublicKeyJwk.kid) {
    return issuerPublicKeyJwk;
  }
  if (kid === notaryPublicKeyJwk.kid) {
    return notaryPublicKeyJwk;
  }
  throw new Error("No verification key found in trust store.");
};
const verifier = await cose.receipt.verifier({
  resolve,
});
const verified = await verifier.verify({
  coseSign1: transparentSignature,
  payload: content,
});
```

## IETF

### RFCs

- [RFC9360 - CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates](https://datatracker.ietf.org/doc/rfc9360/)
- [RFC9052 - CBOR Object Signing and Encryption (COSE): Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC9053 - CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)

### Drafts

- [Concise Encoding of Signed Merkle Tree Proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- [An Architecture for Trustworthy and Transparent Digital Supply Chains](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
