
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';


it('ml_kem768', () => {
  const aliceKeys = ml_kem768.keygen();
  const alicePub = aliceKeys.publicKey;
  const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(alicePub);
  const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);
  expect(aliceShared).toBeDefined()
})

it('ml_dsa65', () => {
  const seed = new TextEncoder().encode('not a safe seed')
  const aliceKeys = ml_dsa65.keygen(seed);
  const msg = new Uint8Array(1);
  const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
  const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
  expect(isValid).toBe(true)
})