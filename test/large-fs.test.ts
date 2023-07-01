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

it('Buffer sanity', async () => {
  const protectedHeader = { alg: 'ES256', kid: log_id }
  const content = fs.readFileSync('1765337807_A cyberpunk painting of trees made of light, zeros_xl-beta-v2-2-2.png')
  const payload = content
  const signed = await signer.sign({ protectedHeader, payload })
  const detached = await cose.detachPayload(signed)
  const attached = await cose.attachPayload(detached)
  const verified = await verifier.verify(attached)
  const recovered = Buffer.from(verified)
  expect(recovered).toEqual(payload)
})
