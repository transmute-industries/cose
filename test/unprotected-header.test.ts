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

it('unprotected header', async () => {
  const protectedHeader = { alg: 'ES256', content_type: 'application/jwk+json' }
  const message = JSON.stringify({
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
    y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
  })
  const payload = new TextEncoder().encode(message)
  const signed = await signer.sign({ protectedHeader, payload })
  const m = new Map()
  m.set(cose.unprotectedHeader.kid, 42)
  const updated = cose.unprotectedHeader.set(signed, m)
  const verified = await verifier.verify(updated)
  expect(new TextDecoder().decode(verified)).toEqual(message)
  const diag = await cose.diagnostic(updated)
  // console.log(diag)
  expect(diag).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a2012603746170706c69636174696f6e2f6a776b2b6a736f6e', 
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "content_type" : h'6170706c69636174696f6e2f6a776b2b6a736f6e',
  #   3 : application/jwk+json
  # }

  # Unprotected Header
  {
      # "kid" : "h'3432'"    
      4 : h'3432' 
  },

  # Protected Payload
  h'7b226b7479223a224543222c22637276223a22502d323536222c22616c67223a224553323536222c2278223a224c59646830495442474c4f55707977793061644678587961496151617049454f4c67667737393333545245222c2279223a22493652336867515a6632746f704f57613056426a45756752674849534a33394c764f6c6656583239503077227d',
  # {"kty":"EC","crv":"P-256","alg":"ES256","x":"LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE","y":"I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w"}

  # Signature
  h'0f92a5be044fa3fd787a77e934147c8a44c3713ff345f6e4b7ce551038428ec3f369c336b736c1ea34ab70e3d72937c409b45dcd7e043a523b7209f8b78e8280'
])`)
})
