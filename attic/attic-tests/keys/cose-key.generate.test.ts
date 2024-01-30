import { base64url } from 'jose'
import cose from '../../src'

it('can generate cose keys', async () => {
  const k0 = await cose.key.generate(-7)
  const k0Edn = cose.key.edn(k0)
  expect(k0Edn.includes('COSE Key')).toBe(true)
  // {                                   / COSE Key                              /
  //   1: 2,                             / Type                                  /
  //   2: h'676f786c...58706f63',        / Identifier                            /
  //   3: -7,                            / Algorithm                             /
  //   -1: 1,                            / Curve                                 /
  //   -2: h'35216751...84518d9a',       / x public key component                /
  //   -3: h'073ba1dd...b84e6b61',       / y public key component                /
  //   -4: h'368e84d7...684d2a58',       / d private key component               /
  // }
  const jwk0 = cose.key.exportJWK(k0)
  // {
  //   kty: 'EC',
  //   kid: '6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg',
  //   alg: 'ES256',
  //   crv: 'P-256',
  //   x: '9YjGAfpSPQ9t8p9zc9eCqzkDGHu_j-0_tTkUvOk5U8E',
  //   y: 'YBFDrB8IROK1G_mu5FceqQnEk4CoFbcz6MyhuQWkCTE',
  //   d: 'FLvNjn-z8HOvl0eGcH8eBYnxZ4xoEKVvCYIB0ibqkfs'
  // }
  expect(jwk0.kty).toBe('EC')
  const jwk1 = {
    kty: 'EC',
    kid: '6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg',
    alg: 'ES256',
    crv: 'P-256',
    x: '9YjGAfpSPQ9t8p9zc9eCqzkDGHu_j-0_tTkUvOk5U8E',
    y: 'YBFDrB8IROK1G_mu5FceqQnEk4CoFbcz6MyhuQWkCTE',
    d: 'FLvNjn-z8HOvl0eGcH8eBYnxZ4xoEKVvCYIB0ibqkfs'
  }
  const k1 = await cose.key.importJWK(jwk1)
  const jkt = await cose.key.thumbprint.calculateJwkThumbprint(jwk1)
  const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(jwk1)
  expect(jktUri).toBe('urn:ietf:params:oauth:jwk-thumbprint:sha-256:6hnb34De4biE17mQd46iSzxMnYPtqy3UaUd22KYZ0xg')
  expect(jkt).toBe(jwk1.kid)
  const jwk2 = await cose.key.exportJWK(k1)
  expect(jwk1).toEqual(jwk2)

  const ckt = await cose.key.thumbprint.calculateCoseKeyThumbprint(k1)
  const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(k1)
  expect(cktUri).toBe('urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJDPXpM4qfsGD_EyGfMa0JZsZNmvYK1lY')
  const decoded = base64url.decode(cktUri.split(':').pop() as string)
  expect(Buffer.from(decoded)).toEqual(Buffer.from(ckt))

  const coseKey2 = new Map();
  coseKey2.set(-2, Buffer.from('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', 'hex'))
  coseKey2.set(-1, 1)
  coseKey2.set(1, 2)
  coseKey2.set(-3, Buffer.from('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', 'hex'))
  const ckt2 = await cose.key.thumbprint.calculateCoseKeyThumbprint(coseKey2)
  expect(Buffer.from(ckt2).toString('hex')).toBe('496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec')
})
