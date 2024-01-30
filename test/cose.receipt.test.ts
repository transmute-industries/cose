


import { CoMETRE } from '@transmute/rfc9162'
import * as transmute from '../src'
const encoder = new TextEncoder();
const entries = [`💣 test`, `✨ test`, `🔥 test`]
  .map((entry) => {
    return encoder.encode(entry)
  })
  .map((entry) => {
    return CoMETRE.RFC9162_SHA256.leaf(entry)
  })

it('issue & verify', async () => {
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
  entries.push(CoMETRE.RFC9162_SHA256.leaf(encoder.encode('✨ new entry ✨')))
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