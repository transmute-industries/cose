
import * as jose from 'jose'

import * as mixed from '../src/mixed'

it('jwe json multiple recipient', async () => {
  const key1 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const key2 = await jose.generateKeyPair('RSA-OAEP-384')
  const message = new TextEncoder().encode('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  const aad = new TextEncoder().encode('💀 aad')
  const jwe = await new jose.GeneralEncrypt(
    message
  )
    .setAdditionalAuthenticatedData(aad)
    .setProtectedHeader({ enc: 'A128GCM' })
    .addRecipient(key1.publicKey)
    .setUnprotectedHeader({ alg: 'ECDH-ES+A128KW' })
    .addRecipient(key2.publicKey)
    .setUnprotectedHeader({ alg: 'RSA-OAEP-384' })
    .encrypt()

  const { plaintext, protectedHeader, additionalAuthenticatedData } = await jose.generalDecrypt(jwe, key1.privateKey) as any;
  expect(new TextDecoder().decode(additionalAuthenticatedData)).toBe('💀 aad')
  expect(new TextDecoder().decode(plaintext)).toBe('✨ It’s a dangerous business, Frodo, going out your door. ✨')

  expect(protectedHeader.enc).toBe('A128GCM')
  expect(protectedHeader.alg).toBeUndefined()
  expect(protectedHeader.epk).toBeUndefined()

  // some extra tests here to confirm key wrapping basics
  const [r0] = jwe.recipients as any;
  const sharedSecret = await mixed.deriveKey(r0.header.epk, await jose.exportJWK(key1.privateKey))
  const encryptedKey = jose.base64url.decode(r0.encrypted_key)
  const cek = mixed.unwrap('A128KW', sharedSecret, encryptedKey)
  const kwkc = Buffer.from(mixed.wrap('A128KW', sharedSecret, cek))
  expect(encryptedKey).toEqual(kwkc)
})


it('jwe json single recipient', async () => {
  const key1 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const message = new TextEncoder().encode('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  const aad = new TextEncoder().encode('💀 aad')
  const jwe = await new jose.GeneralEncrypt(
    message
  )
    .setAdditionalAuthenticatedData(aad)
    .setProtectedHeader({ enc: 'A128GCM' })
    .addRecipient(key1.publicKey)
    .setUnprotectedHeader({ alg: 'ECDH-ES+A128KW' })
    .encrypt()
  const { plaintext, protectedHeader, additionalAuthenticatedData } = await jose.generalDecrypt(jwe, key1.privateKey) as any;
  expect(new TextDecoder().decode(additionalAuthenticatedData)).toBe('💀 aad')
  expect(new TextDecoder().decode(plaintext)).toBe('✨ It’s a dangerous business, Frodo, going out your door. ✨')
  expect(protectedHeader.alg).toBeUndefined()
  expect(protectedHeader.enc).toBe('A128GCM')
  expect(protectedHeader.epk.kty).toBe('EC')
  expect(protectedHeader.epk.crv).toBe('P-256')

})

it('jwe compact', async () => {
  const key1 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const jwe = await new jose.CompactEncrypt(
    new TextEncoder().encode('It’s a dangerous business, Frodo, going out your door.'),
  )
    .setProtectedHeader({ alg: 'ECDH-ES+A128KW', enc: 'A128GCM' })
    .encrypt(key1.publicKey)
  const { plaintext, protectedHeader } = await jose.compactDecrypt(jwe, key1.privateKey) as any
  expect(protectedHeader.alg).toBe('ECDH-ES+A128KW')
  expect(protectedHeader.enc).toBe('A128GCM')
  expect(protectedHeader.epk.kty).toBe('EC')
  expect(protectedHeader.epk.crv).toBe('P-256')
  // protected header also protectes the epk.
  expect(new TextDecoder().decode(plaintext)).toBe('It’s a dangerous business, Frodo, going out your door.')
})