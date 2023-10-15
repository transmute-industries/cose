

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
  const verified = await verifier.verify(signed)
  expect(new TextDecoder().decode(verified)).toEqual(message)
  const diag = await cose.rfc.diag(signed)
  console.log(diag)
  //   expect(diag).toBe(`
  // 18(
  //   [
  //     h'a2012604581c68747470733a2f2f7472616e73706172656e63792e6578616d706c65', 
  //     {},
  //     64(h'68656c6c6f'),
  //     h'6026a1a9641353aa553a74166d01b156cc21c954740059020525bc4d71480a9226dbb9e1e22904da90d2de6f782fa8607c75d1e9137dbfded94a165dbd5f7ad2'
  //   ]
  // )
  // `)
})
