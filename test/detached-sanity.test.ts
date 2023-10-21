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

it('sanity', async () => {
  const protectedHeader = { alg: 'ES256', kid: log_id }
  const message = 'hello'
  const payload = new TextEncoder().encode(message)
  const signed = await signer.sign({ protectedHeader, payload })
  const result = await cose.detachPayload(signed)
  const signed2 = await cose.attachPayload(result)
  const verified = await verifier.verify(signed2)
  expect(new TextDecoder().decode(verified)).toEqual(message)
})
