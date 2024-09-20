import { base64url } from 'jose'

import * as transmute from '../src'

it('generate cose key', async () => {
  const secretKeyJwk1 = await transmute.key.generate<transmute.PrivateKeyJwk>('ES256', 'application/jwk+json')
  const secretKeyCose1 = await transmute.key.convertJsonWebKeyToCoseKey<transmute.key.CoseKey>(secretKeyJwk1)
  expect(secretKeyCose1.get(transmute.EC2.Crv)).toBe(transmute.Curves.P256) // crv : P-256
  const secretKeyCose2 = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  expect(secretKeyCose2.get(transmute.EC2.Crv)).toBe(transmute.Curves.P256) // crv : P-256
  const secretKeyJwk2 = await transmute.key.convertCoseKeyToJsonWebKey<transmute.PrivateKeyJwk>(secretKeyCose1)
  expect(secretKeyJwk2.kid).toBe(secretKeyJwk1.kid) // text identifiers survive key conversion
  expect(secretKeyJwk2.alg).toBe(secretKeyJwk1.alg)
  expect(secretKeyJwk2.kty).toBe(secretKeyJwk1.kty)
  expect(secretKeyJwk2.crv).toBe(secretKeyJwk1.crv)
  expect(secretKeyJwk2.x).toBe(secretKeyJwk1.x)
  expect(secretKeyJwk2.y).toBe(secretKeyJwk1.y)
  expect(secretKeyJwk2.d).toBe(secretKeyJwk1.d)
  const secretKeyJwk3 = await transmute.key.convertCoseKeyToJsonWebKey<transmute.PrivateKeyJwk>(secretKeyCose1)
  const secretKeyCose3 = await transmute.key.convertJsonWebKeyToCoseKey<transmute.key.CoseKey>(secretKeyJwk3)
  const secretKeyJwk4 = await transmute.key.convertCoseKeyToJsonWebKey<transmute.PrivateKeyJwk>(secretKeyCose3)
  expect(secretKeyJwk4.kid).toBe(secretKeyJwk3.kid) // text identifiers survive key conversion

})
it('generate thumbprints', async () => {
  const k1 = {
    kty: 'EC',
    kid: '6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg',
    alg: 'ES256',
    crv: 'P-256',
    x: '9YjGAfpSPQ9t8p9zc9eCqzkDGHu_j-0_tTkUvOk5U8E',
    y: 'YBFDrB8IROK1G_mu5FceqQnEk4CoFbcz6MyhuQWkCTE',
    d: 'FLvNjn-z8HOvl0eGcH8eBYnxZ4xoEKVvCYIB0ibqkfs'
  }
  const jkt = await transmute.key.thumbprint.calculateJwkThumbprint(k1)
  const jktUri = await transmute.key.thumbprint.calculateJwkThumbprintUri(k1)
  expect(jktUri).toBe('urn:ietf:params:oauth:jwk-thumbprint:sha-256:6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg')
  expect(jkt).toBe(k1.kid)
  const k2 = await transmute.key.convertJsonWebKeyToCoseKey<transmute.key.CoseKey>(k1)
  const ckt = await transmute.key.thumbprint.calculateCoseKeyThumbprint(k2)
  const cktUri = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(k2)
  expect(cktUri).toBe('urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJDPXpM4qfsGD_EyGfMa0JZsZNmvYK1lY')
  const decoded = base64url.decode(cktUri.split(':').pop() as string)
  expect(Buffer.from(decoded)).toEqual(Buffer.from(ckt))
})

it('public from private for JWK and cose key', async () => {
  const privateKeyJwk = await transmute.key.generate<transmute.PrivateKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...expectedPublicKeyJwk } = privateKeyJwk
  const publicKeyJwk = transmute.key.publicFromPrivate<transmute.PublicKeyJwk>(privateKeyJwk)
  expect(publicKeyJwk).toEqual(expectedPublicKeyJwk)
  const secretKeyCose = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const expectedPublicKeyCose = new Map(secretKeyCose.entries())
  expectedPublicKeyCose.delete(transmute.EC2.D)
  const publicKeyCose = transmute.key.publicFromPrivate<transmute.key.CoseKey>(secretKeyCose)
  expect(publicKeyCose).toEqual(expectedPublicKeyCose)
})