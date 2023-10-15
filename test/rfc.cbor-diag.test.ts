

import fs from 'fs'
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

const getInclusionProofs = (signed_inclusion_proof: Uint8Array) => {
  const unprotectedHeader = cose.unprotectedHeader.get(signed_inclusion_proof)
  const inclusionProof = cose.cbor.web.decode(unprotectedHeader.get(100) as Buffer)
  return inclusionProof
}

it('signed inclusion proof', async () => {
  const message0 = cose.cbor.web.encode(0)
  const message1 = cose.cbor.web.encode('1')
  const message2 = cose.cbor.web.encode([2, 2])
  const message3 = cose.cbor.web.encode({ 3: 3 })
  const entries = [message0, message1, message2, message3]
  const leaves = entries.map(cose.merkle.leaf)
  const signed_inclusion_proof = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: log_id,
    leaf_index: 2,
    leaves,
    signer,
  })
  const verified1 = await cose.merkle.verify_inclusion_proof(
    {
      leaf: cose.merkle.leaf(entries[2]),
      signed_inclusion_proof,
      verifier
    }
  )
  expect(verified1).toBe(true)

  const signed_inclusion_proof2 = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: log_id,
    leaf_index: 3,
    leaves,
    signer,
  })
  const verified2 = await cose.merkle.verify_inclusion_proof(
    {
      leaf: cose.merkle.leaf(entries[3]),
      signed_inclusion_proof: signed_inclusion_proof2,
      verifier
    }
  )
  expect(verified2).toBe(true)

  // Add a second inclusion proof to a previous received signed inclusion proof
  // TODO move to a utility function
  const firstProofs = getInclusionProofs(signed_inclusion_proof)
  const secondProofs = getInclusionProofs(signed_inclusion_proof2)
  const unprotectedHeader = cose.unprotectedHeader.get(signed_inclusion_proof)
  unprotectedHeader.set(100, cose.cbor.web.encode([...firstProofs, ...secondProofs]))
  const updated = cose.unprotectedHeader.set(signed_inclusion_proof, unprotectedHeader)
  const verified3 = await cose.merkle.verify_multiple(
    {
      leaves: [cose.merkle.leaf(entries[2]), cose.merkle.leaf(entries[3])],
      signed_inclusion_proof: updated,
      verifier
    }
  )
  expect(verified3).toBe(true)
  const diag = await cose.rfc.diag(updated)
  fs.writeFileSync('inclusion-proof.cbor.md', diag)

})
