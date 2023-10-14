import cose, { CoseSigner, CoseVerifier } from '../src'
import merkle from '../src/merkle'

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

const message0 = cose.cbor.web.encode(0)
const message1 = cose.cbor.web.encode('1')
const message2 = cose.cbor.web.encode([2, 2])
const message3 = cose.cbor.web.encode({ 3: 3 })
const message4 = cose.cbor.web.encode(['🔥', 4])
const message5 = cose.cbor.web.encode({ five: '💀' })

const c1: Uint8Array[] = []
const c2: Uint8Array[] = []

it('clients send entries to the server as they see them', async () => {
  c1.push(message0)
  c1.push(message1)

  c2.push(message0)
  c2.push(message1)
  c2.push(message2)
  c2.push(message3)

  // c1 requests inclusion proof for m1 from c2
  const ip1 = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: 'urn:trans:c2',
    leaf_index: 1,
    leaves: c2.map(merkle.leaf),
    signer,
  })

  // c1 gets new messages
  c1.push(message2)
  c1.push(message3)

  // c1 learns c2 has m1
  await cose.merkle.verify_inclusion_proof({
    leaf: cose.merkle.leaf(message1),
    signed_inclusion_proof: ip1,
    verifier,
  }),
    // c2 gets new messages
    c2.push(message4)

  // c1 requests consistency proof from c2
  const cp1 = await cose.merkle.consistency_proof({
    alg: signer.alg,
    kid: 'urn:trans:c2',
    signed_inclusion_proof: ip1,
    leaves: c2.map(merkle.leaf),
    signer,
  })

  // c1 gets new messages
  c1.push(message4)

  // c2 gets new messages
  c2.push(message5)

  // c1 learns c2 is append only, and has new entries
  await cose.merkle.verify_consistency_proof({
    old_root: await merkle.root({
      alg: signer.alg,
      kid: 'urn:trans:c2',
      // c1 knows c2 has at least up to the previous inclusion proof size
      leaves: c1.slice(0, 4).map(merkle.leaf),
    }),
    signed_consistency_proof: cp1,
    verifier,
  })

  c1.push(message5)
})
