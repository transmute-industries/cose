
import * as transmute from '../src'

it('sign and verify', async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.attached.signer({ secretKeyJwk })
  const message = '💣 test ✨ mesage 🔥'
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload: new TextEncoder().encode(message)
  })
  // ... the network ...
  const verifier = transmute.attached.verifier({ publicKeyJwk })
  const verified = await verifier.verify({ coseSign1 })
  expect(new TextDecoder().decode(verified)).toBe(message)
})