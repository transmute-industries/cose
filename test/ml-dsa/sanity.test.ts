
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

it('ml_dsa65', () => {
  const seed = new TextEncoder().encode('not a safe seed')
  const aliceKeys = ml_dsa65.keygen(seed);
  const msg = new Uint8Array(1);
  const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
  const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
  expect(isValid).toBe(true)
})