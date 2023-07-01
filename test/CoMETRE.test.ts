import cose, { CoseSigner, CoseVerifier } from '../src'

const log_id = `https://transparency.example`
let signer: CoseSigner
let verifier: CoseVerifier

beforeAll(async () => {
  signer = await cose.signer({
    privateKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      d: 'o_95vWSheg19YU7viU3PmW_kRIWk14HiVLXDXiZjEL0',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
  verifier = await cose.verifier({
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
})

const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })
const entries = [message0, message1, message2, message3]
const leaves = entries.map(cose.merkle.leaf)

const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
entries.push(message4)
entries.push(message5)
const leaves2 = entries.map(cose.merkle.leaf)

it('message sanity', async () => {
  expect(cose.cbor.decode(message0)).toEqual(0)
  expect(cose.cbor.decode(message1)).toEqual('1')
  expect(cose.cbor.decode(message2)).toEqual([2, 2])
  expect(cose.cbor.decode(message3)).toEqual({ 3: 3 })
  expect(cose.cbor.decode(message4)).toEqual(['🔥', 4])
  expect(cose.cbor.decode(message5)).toEqual({ five: '💀' })
})

let signed_inclusion_proof: Uint8Array

it('inclusion proof', async () => {
  signed_inclusion_proof = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: log_id,
    leaf_index: 2,
    leaves,
    signer,
  })
  const verified_inclusion_proof = await cose.merkle.verify_inclusion_proof({
    leaf: cose.merkle.leaf(entries[2]),
    signed_inclusion_proof,
    verifier,
  })

  expect(cose.binToHex(verified_inclusion_proof)).toBe(
    '0bdaaed3b6301858b0acbda1e0c3aa55f2de037ced44253ae6797b5a32568964',
  )
  const old_root = await cose.merkle.root({
    alg: signer.alg,
    kid: log_id, leaves
  })
  const attached = await cose.attachPayload({
    signature: signed_inclusion_proof,
    payload: old_root
  })
  const verified_root = await verifier.verify(attached)
  expect(verified_root).toEqual(old_root)
})

it('consistency proof', async () => {
  const old_root = await cose.merkle.root({
    alg: signer.alg,
    kid: log_id, leaves
  })
  const new_root = await cose.merkle.root({
    alg: signer.alg,
    kid: log_id, leaves: leaves2
  })
  const signed_consistency_proof = await cose.merkle.consistency_proof({
    alg: signer.alg,
    kid: log_id,
    signed_inclusion_proof,
    leaves: leaves2,
    signer,
  })
  const verified = await cose.merkle.verify_consistency_proof({
    old_root,
    signed_consistency_proof,
    verifier,
  })
  expect(verified).toBe(true)
  const verified_root = await verifier.verify(signed_consistency_proof)
  expect(verified_root).toEqual(new_root)
})
