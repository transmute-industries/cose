
import * as transmute from '../src'

it('generate cose key', async () => {
  const secretKeyJwk1 = await transmute.key.generate<transmute.JsonWebKey>('ES256', 'application/jwk+json')
  const secretKeyCose1 = await transmute.key.convertJsonWebKeyToCoseKey(secretKeyJwk1)
  expect(secretKeyCose1.get(-1)).toBe(1) // crv : P-256
  const secretKeyCose2 = await transmute.key.generate<transmute.CoseKey>('ES256', 'application/cose-key')
  expect(secretKeyCose2.get(-1)).toBe(1) // crv : P-256
})