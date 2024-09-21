import * as jose from 'jose'

import { fully_specified_web_key, generate_web_key } from '../src/draft'

it('without type safety', async () => {
  const k = await jose.generateKeyPair('ES256')
  const publicKey = await jose.exportJWK(k.publicKey)
  const { kty, crv, alg, x } = publicKey
  expect(alg === undefined).toBe(true) // bad but legal
  expect(kty).toBe('EC')
  expect(crv).toBe('P-256') // string, but we know it must be P-256
  expect(x).toBeDefined()
})

it('fully specified key', async () => {
  const { publicKey } = await generate_web_key({ alg: 'ES256', ext: true })
  const { kid, kty, crv, alg, x } = publicKey
  expect(kid).toBeDefined() // default key identifier
  expect(alg === 'ES256').toBe(true) // good (and with type checking)
  expect(kty).toBe('EC')
  expect(crv).toBe('P-256') // type specifies the curve and algorithm fully
  expect(x).toBeDefined()
})

it('custom key identifier', async () => {
  const { publicKey } = await generate_web_key({ alg: 'ES256', ext: true, kid: 'magic-key-42' })
  type extended_web_key_type = fully_specified_web_key<'ES256'> & Required<{ kid: 'magic-key-42' }>
  const k = publicKey as extended_web_key_type
  expect(k.kid).toBe('magic-key-42') // type safe key identifier
})


