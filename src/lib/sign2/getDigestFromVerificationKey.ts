import { VerifierKeyJwk } from './VerifierKeyJwk'
const joseToCose = new Map<string, string>()

joseToCose.set('ES256', `SHA-256`)
joseToCose.set('ES384', `SHA-384`)
joseToCose.set('ES512', `SHA-512`)

const getDigestFromVerificationKey = (jwk: VerifierKeyJwk): string => {
  const alg = joseToCose.get(jwk.alg)
  if (!alg) {
    throw new Error('This library requires verification keys contain fully specified algorithms')
  }
  return alg
}

export default getDigestFromVerificationKey