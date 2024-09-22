


import fs from 'fs'
import { JWK } from 'jose'
import * as cose from '../src'
const encoder = new TextEncoder();

it('issue & verify', async () => {

  const entries = await Promise.all([`💣 test`, `✨ test`, `🔥 test`]
    .map((entry) => {
      return encoder.encode(entry)
    })
    .map((entry) => {
      return cose.receipt.leaf(entry)
    }))


  const privateKeyJwk = await cose.crypto.key.gen<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = privateKeyJwk
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  })
  const inclusion = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 1,
    entries,
    signer
  })
  const oldVerifiedRoot = await cose.receipt.inclusion.verify({
    entry: entries[1],
    receipt: inclusion,
    verifier
  })
  // because entries are stable, verified root is stable.
  expect(Buffer.from(oldVerifiedRoot).toString('hex')).toBe('d82bd9d3f1e3dd82506d1ab09dd2ed6790596b1a2fe95a64d504dc9e2f90dab6')
  // new entries are added over time.
  entries.push(await cose.receipt.leaf(encoder.encode('✨ new entry ✨')))
  // ask the transparency service for the latest root, and a consistency proof
  // based on a previous receipt
  const { root, receipt } = await cose.receipt.consistency.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    receipt: inclusion,
    entries,
    signer
  })
  const consistencyValidated = await cose.receipt.consistency.verify({
    oldRoot: oldVerifiedRoot,
    newRoot: root,
    receipt: receipt,
    verifier
  })
  expect(consistencyValidated).toBe(true)
})

it("add / remove from receipts", async () => {
  const privateKeyJwk = await cose.key.generate<JWK>('ES256', 'application/jwk+json')
  const publicKeyJwk = await cose.key.publicFromPrivate<JWK>(privateKeyJwk)
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256], // alg ES256
      [cose.header.content_type, "image/png"], // content_type image/png
    ]),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await cose.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer
  })
  const transparentSignature = await cose.receipt.add(signatureForImage, receiptForImageSignature)
  const { value } = cose.cbor.decode(transparentSignature)
  expect(value[1].get(cose.draft_headers.receipts).length).toBe(1) // expect 1 receipt
  const receipts = await cose.receipt.get(transparentSignature)
  expect(receipts.length).toBe(1) // expect 1 receipt
  const coseKey = await cose.key.convertJsonWebKeyToCoseKey<cose.any_cose_key>(publicKeyJwk)
  coseKey.set(cose.ec2.kid, await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey))
  const publicKey = cose.key.serialize<Buffer>(coseKey)
  expect(publicKey).toBeDefined();
  // fs.writeFileSync('./examples/image.ckt.signature.cbor', Buffer.from(transparentSignature))
  // fs.writeFileSync('./examples/image.ckt.public-key.cbor', publicKey)
})

