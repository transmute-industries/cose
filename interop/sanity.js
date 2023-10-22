
const fs = require('fs');
const cose = require('@transmute/cose').default;

const makeDilithiumReadme = async () => {
  const publicKey = fs.readFileSync('dilithium.publicKey.cose');
  const publicKeyMap = cose.cbor.decode(publicKey)
  const publicKeyDiagnostic = cose.key.edn(publicKeyMap)

  const secretKey = fs.readFileSync('dilithium.secretKey.cose');
  const secretKeyMap = cose.cbor.decode(secretKey)
  const secretKeyDiagnostic = cose.key.edn(secretKeyMap)

  const sign12 = fs.readFileSync('dilithium.sign1.cose');
  const items = await cose.rfc.diag(new Uint8Array(sign12))

  const doc = `
# Proposal

[Read the draft](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 7,                             / ✨ 7 is MLWE                  /
  2: h'85eb5426...533214a2',        / Identifier                    /
  3: -55555,                        / ✨ -55555 is CRYDI2           /
  -13: h'fbd0006c...f2f88c9c',      / ✨ private key for 7          /
  -14: h'fbd0006c...f2f88c9c',      / ✨ public key for 7           /
}
~~~~

## Current

### Public Key
${publicKeyDiagnostic}

### Secret Key
${secretKeyDiagnostic}

### Envelope

${items.map((block) => {

    return `
~~~~ cbor-diag
${block.trim()}
~~~~
  `.trim()

  }).join('\n\n')}

  `
  fs.writeFileSync('README.md', doc)
}

(async () => {
  await makeDilithiumReadme()
})()


