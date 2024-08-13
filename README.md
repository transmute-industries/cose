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

### SCITT Receipts

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

const issuer = cose.detached.signer({
  remote: cose.crypto.signer({
    privateKeyJwk: issuerSecretKeyJwk,
  }),
});
const notary = cose.detached.signer({
  remote: cose.crypto.signer({
    privateKeyJwk: notarySecretKeyJwk,
  }),
});
const content = fs.readFileSync("./examples/image.png");
const signatureForImage = await issuer.sign({
  protectedHeader: cose.ProtectedHeader([
    [cose.Protected.Alg, cose.Signature.ES256], // signing algorithm ES256
    [cose.Protected.ContentType, "image/png"], // content type image/png
    [cose.Protected.Kid, issuerPublicKeyJwk.kid], // issuer key identifier
  ]),
  payload: content,
});
const transparencyLogContainingImageSignatures = [
  await cose.receipt.leaf(signatureForImage),
];
const receiptForImageSignature = await cose.receipt.inclusion.issue({
  protectedHeader: cose.ProtectedHeader([
    [cose.Protected.Alg, cose.Signature.ES256],
    [
      cose.Protected.VerifiableDataStructure,
      cose.VerifiableDataStructures["RFC9162-Binary-Merkle-Tree"],
    ],
    [cose.Protected.Kid, notaryPublicKeyJwk.kid],
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
  coseSign1: cose.CoseSign1Bytes
): Promise<cose.PublicKeyJwk> => {
  const { tag, value } = cose.cbor.decodeFirstSync(coseSign1);
  if (tag !== cose.COSE_Sign1) {
    throw new Error("Only tagged cose sign 1 are supported");
  }
  const [protectedHeaderBytes] = value;
  const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes);
  const kid = protectedHeaderMap.get(cose.Protected.Kid);
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

### HPKE

```ts
const message = "💀 My lungs taste the air of Time Blown past falling sands ⌛";
const plaintext = new TextEncoder().encode(message);
const encryptionKeys = {
  keys: [
    {
      kid: "meriadoc.brandybuck@buckland.example",
      alg: "HPKE-Base-P256-SHA256-AES128GCM",
      kty: "EC",
      crv: "P-256",
      x: "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
      y: "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    },
  ],
};
const decryptionKeys = {
  keys: [
    {
      kid: "meriadoc.brandybuck@buckland.example",
      alg: "HPKE-Base-P256-SHA256-AES128GCM",
      kty: "EC",
      crv: "P-256",
      x: "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
      y: "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
      d: "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
    },
  ],
};
const ciphertext = await cose.encrypt.direct({
  protectedHeader: ProtectedHeader([
    [Protected.Alg, Direct["HPKE-Base-P256-SHA256-AES128GCM"]],
  ]),
  plaintext,
  recipients: encryptionKeys,
});
const decrypted = await cose.decrypt.direct({
  ciphertext,
  recipients: decryptionKeys,
});
```

### COSE RFCs

- [RFC9360 - Header Parameters for Carrying and Referencing X.509 Certificates](https://datatracker.ietf.org/doc/rfc9360/)
- [RFC9052 - Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC9053 - Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)

### COSE Drafts

- [COSE Receipts](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- [COSE HPKE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)

### SCITT Drafts

- [An Architecture for Trustworthy and Transparent Digital Supply Chains](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
