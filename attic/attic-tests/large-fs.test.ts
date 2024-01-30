import fs from 'fs'
import cose, { CoseDetachedSigner, CoseDetachedVerifier } from '../src'

const log_id = `https://transparency.example`

let signer: CoseDetachedSigner
let verifier: CoseDetachedVerifier

beforeAll(async () => {
  signer = await cose.detached.signer({
    privateKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      d: 'o_95vWSheg19YU7viU3PmW_kRIWk14HiVLXDXiZjEL0',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
  verifier = await cose.detached.verifier({
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
})

it('detached api large objects', async () => {
  const protectedHeader = { alg: 'ES256', kid: log_id, content_type: 'image/png' }
  const content = fs.readFileSync('./test/1765337807_A cyberpunk painting of trees made of light, zeros_xl-beta-v2-2-2.png')
  const { payload, signature, } = await signer.sign({ protectedHeader, payload: content })
  const verified = await verifier.verify({ payload, signature, })
  const contentType = cose.getContentType(signature)
  expect(contentType).toBe('image/png')
  expect(verified).toBe(true)
})
