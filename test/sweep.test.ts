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

it('sweep test', async () => {
  const leaves: Uint8Array[] = []
  for (let i = 0; i < 10; i++) {
    const message = `${i}`
    const leaf = cose.merkle.leaf(cose.cbor.encode(message))
    leaves.push(leaf)
    const proof = await cose.merkle.inclusion_proof({
      alg: signer.alg,
      kid: log_id,
      leaf_index: i,
      leaves,
      signer,
    })
    const verified_inclusion_proof = await cose.merkle.verify_inclusion_proof({
      leaf: leaf,
      signed_inclusion_proof: proof,
      verifier,
    })
    expect(verified_inclusion_proof).toBeDefined()
  }
})
