


import fs from 'fs'

import * as transmute from '../src'
const encoder = new TextEncoder();

it('issue & verify', async () => {

  const entries = await Promise.all([`💣 test`, `✨ test`, `🔥 test`]
    .map((entry) => {
      return encoder.encode(entry)
    })
    .map((entry) => {
      return transmute.receipt.leaf(entry)
    }))


  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.detached.signer({ secretKeyJwk })
  const verifier = transmute.detached.verifier({ publicKeyJwk })
  const inclusion = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map([
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 1,
    entries,
    signer
  })
  const oldVerifiedRoot = await transmute.receipt.inclusion.verify({
    entry: entries[1],
    receipt: inclusion,
    verifier
  })
  // because entries are stable, verified root is stable.
  expect(Buffer.from(oldVerifiedRoot).toString('hex')).toBe('d82bd9d3f1e3dd82506d1ab09dd2ed6790596b1a2fe95a64d504dc9e2f90dab6')
  // new entries are added over time.
  entries.push(await transmute.receipt.leaf(encoder.encode('✨ new entry ✨')))
  // ask the transparency service for the latest root, and a consistency proof
  // based on a previous receipt
  const { root, receipt } = await transmute.receipt.consistency.issue({
    protectedHeader: new Map([
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    receipt: inclusion,
    entries,
    signer
  })
  const consistencyValidated = await transmute.receipt.consistency.verify({
    oldRoot: oldVerifiedRoot,
    newRoot: root,
    receipt: receipt,
    verifier
  })
  expect(consistencyValidated).toBe(true)
})

it("add / remove from receipts", async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  const publicKeyJwk = await transmute.key.publicFromPrivate<transmute.PublicKeyJwk>(secretKeyJwk)
  const signer = transmute.detached.signer({ secretKeyJwk })
  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await signer.sign({
    protectedHeader: new Map<number, any>([
      [1, -7], // alg ES256
      [3, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await transmute.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map([
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer
  })
  const transparentSignature = await transmute.receipt.add(signatureForImage, receiptForImageSignature)
  const { value } = transmute.cbor.decode(transparentSignature)
  expect(value[1].get(394).length).toBe(1) // expect 1 receipt
  const receipts = await transmute.receipt.get(transparentSignature)
  expect(receipts.length).toBe(1) // expect 1 receipt
  const coseKey = transmute.key.convertJsonWebKeyToCoseKey(publicKeyJwk)
  coseKey.set(2, await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey))
  const publicKey = transmute.key.serialize<Buffer>(coseKey)
  expect(publicKey).toBeDefined();
  // fs.writeFileSync('./examples/image.ckt.signature.cbor', Buffer.from(transparentSignature))
  // fs.writeFileSync('./examples/image.ckt.public-key.cbor', publicKey)
})

