import { PublicKeyJwk, SecretKeyJwk } from './types'
const joseToCose = new Map<string, string>()

joseToCose.set('ES256', `SHA-256`)
joseToCose.set('ES384', `SHA-384`)
joseToCose.set('ES512', `SHA-512`)

const getDigestFromVerificationKey = (jwk: PublicKeyJwk | SecretKeyJwk): string => {
  const alg = joseToCose.get(jwk.alg)
  if (!alg) {
    throw new Error('This library requires keys to contain fully specified algorithms')
  }
  return alg
}

export default getDigestFromVerificationKey