

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
  // console.log(diag)
  expect(diag).toBe(`
~~~~ cbor-diag
{
  1: -7,                      / Cryptographic algorithm to use        /
  4: h'68747470...6d706c65'   / Key identifier                        /
}
~~~~

~~~~ cbor-diag
18(                           / COSE Single Signer Data Object        /
    [
      h'a2012604...6d706c65', / Protected header encoded as bstr      /
      {},                     / Unprotected header as a map           /
      h'68656c6c6f',          / Content of the message as bstr or nil /
      h'cf003825...f949855e'  / Signature value as bstr               /
    ]
)
~~~~
  `.trim())

})
