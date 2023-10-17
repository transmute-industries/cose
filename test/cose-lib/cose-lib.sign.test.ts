import cose from '../../src'
import * as jose from 'jose'

const signer = {
  key: {
    d: Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex')
  }
};
const verifier = {
  key: {
    x: Buffer.from('143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f', 'hex'),
    y: Buffer.from('60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9', 'hex')
  }
};

const plaintext = Buffer.from('Important message!');

it('e2e signer verifier', async () => {
  const privateKey = {
    'alg': 'ES256',
    kty: 'EC',
    crv: 'P-256',
    x: jose.base64url.encode(verifier.key.x),
    y: jose.base64url.encode(verifier.key.y),
    d: jose.base64url.encode(signer.key.d),
  }
  const protectedHeader = new Map();
  protectedHeader.set(1, -7)
  const unprotectedHeader = new Map();
  const signature = await cose.lib.create(protectedHeader, unprotectedHeader, plaintext, privateKey);
  const publicKey = {
    'alg': 'ES256',
    kty: 'EC',
    crv: 'P-256',
    x: jose.base64url.encode(verifier.key.x),
    y: jose.base64url.encode(verifier.key.y)
  }
  const verified2 = await cose.lib.verify(signature, publicKey);
  expect(verified2.toString('utf8')).toBe('Important message!')
})
