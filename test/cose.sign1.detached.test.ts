// import fs from 'fs'
import * as transmute from '../src'

it('sign and verify', async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.detached.signer({ secretKeyJwk })
  const message = '💣 test ✨ mesage 🔥'
  const payload = new TextEncoder().encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload
  })
  const { tag, value } = await transmute.cbor.decode(coseSign1)
  expect(tag).toBe(18) // cose sign 1
  expect(value[2]).toBe(undefined) // detached payload

  // ... the network ...
  const verifier = transmute.detached.verifier({ publicKeyJwk })
  const verified = await verifier.verify({ coseSign1, payload })
  expect(new TextDecoder().decode(verified)).toBe(message)

  // fs.writeFileSync('./examples/detached.cose-sign1.cbor', Buffer.from(coseSign1))
})