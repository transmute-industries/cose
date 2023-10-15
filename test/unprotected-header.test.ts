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


const mapsAreEqual = (m1: Map<any, any>, m2: Map<any, any>) => m1.size === m2.size && Array.from(m1.keys()).every((key) => {
  const condition = m1.get(key) === m2.get(key)
  if (!condition) {
    console.log(m1.get(key))
    console.log(m2.get(key))
  }
  return condition
});

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
  // no unprotected header required...
  const signed = await signer.sign({ protectedHeader, payload })
  const m1 = cose.unprotectedHeader.get(signed)
  const m2 = new Map()
  // ensure an undefined unprotected year yields an empty map...
  expect(mapsAreEqual(m1, m2)).toBe(true)
  m2.set(cose.unprotectedHeader.kid, 42)
  const updated = cose.unprotectedHeader.set(signed, m2)
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
  h'6a2c8ef02ca0d75c42ae71a409b1bd7778eeed417df341205f1aacf1f81a92a24940fff06d250a57d6ed1f625b71f05d1cf56d129954a8eab447ac4ed57b328f'
])`)
})
