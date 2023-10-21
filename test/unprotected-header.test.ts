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
  expect(diag).toBeDefined()

})
