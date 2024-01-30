
import * as transmute from '../src'

it('generate cose key', async () => {
  const secretKeyJwk1 = await transmute.key.generate<transmute.JsonWebKey>('ES256', 'application/jwk+json')
  const secretKeyCose1 = await transmute.key.convertJsonWebKeyToCoseKey(secretKeyJwk1)
  expect(secretKeyCose1.get(-1)).toBe(1) // crv : P-256
  const secretKeyCose2 = await transmute.key.generate<transmute.CoseKey>('ES256', 'application/cose-key')
  expect(secretKeyCose2.get(-1)).toBe(1) // crv : P-256

  const secretKeyJwk2 = await transmute.key.convertCoseKeyToJsonWebKey(secretKeyCose1)

  expect(secretKeyJwk2.kid).toBe(secretKeyJwk1.kid) // text identifiers survive key conversion

  expect(secretKeyJwk2.alg).toBe(secretKeyJwk1.alg)

  expect(secretKeyJwk2.kty).toBe(secretKeyJwk1.kty)
  expect(secretKeyJwk2.crv).toBe(secretKeyJwk1.crv)

  expect(secretKeyJwk2.x).toBe(secretKeyJwk1.x)
  expect(secretKeyJwk2.y).toBe(secretKeyJwk1.y)
  expect(secretKeyJwk2.d).toBe(secretKeyJwk1.d)

  const secretKeyJwk3 = await transmute.key.convertCoseKeyToJsonWebKey(secretKeyCose1)
  const secretKeyCose3 = await transmute.key.convertJsonWebKeyToCoseKey(secretKeyJwk3)
  const secretKeyJwk4 = await transmute.key.convertCoseKeyToJsonWebKey(secretKeyCose3)
  expect(secretKeyJwk4.kid).toBe(secretKeyJwk3.kid) // text identifiers survive key conversion


})