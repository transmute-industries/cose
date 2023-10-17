import cose from '../../src'


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

const plaintext = 'Important message!';

const headers = {
  p: { alg: 'ES256' },
  u: { kid: '11' }
};

it('e2e signer verifier', async () => {
  const signature = await cose.lib.sign.create(headers, plaintext, signer);
  const verified = await cose.lib.sign.verify(signature, verifier);
  expect(verified.toString('utf8')).toBe('Important message!')
  const verified2 = await cose.lib.sign2.verify(signature, verifier);
  expect(verified2.toString('utf8')).toBe('Important message!')
})
