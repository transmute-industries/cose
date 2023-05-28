import cose, { CoseSigner, CoseVerifier } from '../src'

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
  const protectedHeader = { alg: 'ES256' }
  const message = 'hello'
  const payload = new TextEncoder().encode(message)
  const signed = await signer.sign({ protectedHeader, payload })
  const diag = await cose.diagnostic(signed)
  const verified = await verifier.verify(signed)
  expect(new TextDecoder().decode(verified)).toEqual(message)
  expect(diag).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a10126', 
  # {
  #   "alg" : "ES256",
  #   1 : -7
  # }

  # Unprotected Header
  {},

  # Protected Payload
  h'68656c6c6f',
  # hello

  # Signature
  h'bfd4fc1bf92161f22b5f2526fccae9875bb28158498b30e079771dcf3e74f13c903a5c44230f170cd1f0ab2d3cb5f97e84c003274fa0367b538b1992ec633a0e'
])`)
})
