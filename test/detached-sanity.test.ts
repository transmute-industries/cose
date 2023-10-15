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

  expect(await cose.diagnostic(result.signature)).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a2012604581c68747470733a2f2f7472616e73706172656e63792e6578616d706c65', 
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "kid" : h'68747470733a2f2f7472616e73706172656e63792e6578616d706c65',
  #   4 : https://transparency.example
  # }

  # Unprotected Header
  {},

  # Protected Payload
  h'',
  # 

  # Signature
  h'cf003825396525d316854242d937881bf1a0a9faedb2e39fe126d2f56d1a2e96457a4d69bdc6aeccbd578601c2bb9607c2f7c65d10e5f6c05f915c86f949855e'
])`)
  const signed2 = await cose.attachPayload(result)
  expect(await cose.diagnostic(signed2)).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a2012604581c68747470733a2f2f7472616e73706172656e63792e6578616d706c65', 
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "kid" : h'68747470733a2f2f7472616e73706172656e63792e6578616d706c65',
  #   4 : https://transparency.example
  # }

  # Unprotected Header
  {},

  # Protected Payload
  h'68656c6c6f',
  # hello

  # Signature
  h'cf003825396525d316854242d937881bf1a0a9faedb2e39fe126d2f56d1a2e96457a4d69bdc6aeccbd578601c2bb9607c2f7c65d10e5f6c05f915c86f949855e'
])`)
  const verified = await verifier.verify(signed2)
  expect(new TextDecoder().decode(verified)).toEqual(message)
})
