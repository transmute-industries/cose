import * as transmute from '../src'
import * as jose from 'jose'
import cose from 'cose-js'

const secretKeyJwk = {
  alg: 'ES256',
  kty: 'EC',
  crv: 'P-256',
  x: jose.base64url.encode(Buffer.from('143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f', 'hex')),
  y: jose.base64url.encode(Buffer.from('60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9', 'hex')),
  d: jose.base64url.encode(Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex')),
}
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const { d, ...publicKeyJwk } = secretKeyJwk

const protectedHeader = new Map();
protectedHeader.set(1, -7)
const unprotectedHeader = new Map();

const message = 'hello'
const payload = Buffer.from(new TextEncoder().encode(message))

it('cross test sign and verify', async () => {
  const s1 = await cose.sign.create(
    { p: { 'alg': 'ES256' }, u: unprotectedHeader },
    payload,
    {
      key: {
        d: jose.base64url.decode(secretKeyJwk.d),
      },
    },
  )
  const v1 = await cose.sign.verify(s1, {
    key: {
      x: jose.base64url.decode(publicKeyJwk.x),
      y: jose.base64url.decode(publicKeyJwk.y),
    },
  })
  expect(new TextDecoder().decode(v1)).toBe(message)
  const s2 = await transmute.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk
    })
  }).sign({
    protectedHeader,
    unprotectedHeader,
    payload: payload
  });
  const v2 = await transmute.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  }).verify({ coseSign1: s2 });
  expect(new TextDecoder().decode(v2)).toBe(message)
  const v3 = await cose.sign.verify(s2, {
    key: {
      x: jose.base64url.decode(publicKeyJwk.x),
      y: jose.base64url.decode(publicKeyJwk.y),
    },
  })
  expect(new TextDecoder().decode(v3)).toBe(message)
  const v4 = await transmute.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  }).verify({ coseSign1: s1 });
  expect(new TextDecoder().decode(v4)).toBe(message)
})
