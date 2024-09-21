import { base64url } from 'jose'

import * as cose from '../src'

it('ES256', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json');
  expect(privateKeyJwk.alg).toBe('ES256')
})

it('conversion', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json');
  const privateKeyCose = await cose.key.convertJsonWebKeyToCoseKey<cose.ec2_key>(privateKeyJwk)
  const privateKey = await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(privateKeyCose)
  expect(privateKey.alg).toBe('ES256')
})

it('thumbprint', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json');
  const privateKeyCose = await cose.key.convertJsonWebKeyToCoseKey<cose.ec2_key>(privateKeyJwk)
  const privateKey = await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(privateKeyCose)
  expect(privateKey.alg).toBe('ES256')
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
  const jkt = await cose.key.thumbprint.calculateJwkThumbprint(k1)
  const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(k1)
  expect(jktUri).toBe('urn:ietf:params:oauth:jwk-thumbprint:sha-256:6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg')
  expect(jkt).toBe(k1.kid)
  const k2 = await cose.key.convertJsonWebKeyToCoseKey<cose.key.CoseKey>(k1)
  const ckt = await cose.key.thumbprint.calculateCoseKeyThumbprint(k2)
  const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(k2)
  expect(cktUri).toBe('urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJDPXpM4qfsGD_EyGfMa0JZsZNmvYK1lY')
  const decoded = base64url.decode(cktUri.split(':').pop() as string)
  expect(Buffer.from(decoded)).toEqual(Buffer.from(ckt))
})

it('public from private', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...expectedPublicKeyJwk } = privateKeyJwk
  const publicKeyJwk = cose.key.publicFromPrivate<cose.PublicKeyJwk>(privateKeyJwk)
  expect(publicKeyJwk).toEqual(expectedPublicKeyJwk)
  const privateKeyCose = await cose.key.generate<cose.key.CoseKey>('ES256', 'application/cose-key')
  const expectedPublicKeyCose = new Map(privateKeyCose.entries())
  expectedPublicKeyCose.delete(cose.EC2.D)
  const publicKeyCose = cose.key.publicFromPrivate<cose.key.CoseKey>(privateKeyCose)
  expect(publicKeyCose).toEqual(expectedPublicKeyCose)
})