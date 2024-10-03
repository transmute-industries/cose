import * as jose from 'jose'

import { fully_specified_web_key, generate_web_key } from '../src/drafts/draft-ietf-jose-fully-specified-algorithms'

it('without type safety', async () => {
  const { publicKey } = await jose.generateKeyPair('ES256')
  const { kty, crv, alg, x } = await jose.exportJWK(publicKey)
  expect(alg).toBeUndefined() // bad... but legal
  // kty has type string,
  expect(kty).toBe('EC') // ... but we know it must be EC
  // crv has type string,
  expect(crv).toBe('P-256') // ... but we know it must be P-256
  expect(x).toBeDefined()
})

it('fully specified key', async () => {
  // type specifies the curve and algorithm fully
  const { publicKey: { kty, crv, alg, x } } = await generate_web_key({ alg: 'ES256', ext: true })
  expect(alg).toBe('ES256') // narrowed
  expect(kty).toBe('EC')    // narrowed
  expect(crv).toBe('P-256') // narrowed
  expect(x).toBeDefined()
})

it('custom key identifier', async () => {
  const { publicKey } = await generate_web_key({ alg: 'ES256', ext: true, kid: 'magic-key-42' })
  type extended_web_key_type = fully_specified_web_key<'ES256'> & Required<{ kid: 'magic-key-42' }>
  const k = publicKey as extended_web_key_type
  expect(k.kid).toBe('magic-key-42') // type safe key identifier
})
