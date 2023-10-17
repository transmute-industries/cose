import { VerifierKeyJwk } from './VerifierKeyJwk'
const joseToCose = new Map<string, number>()

joseToCose.set('ES256', -7)
joseToCose.set('ES384', -35)
joseToCose.set('ES512', -36)

const getAlgFromVerificationKey = (jwk: VerifierKeyJwk): number => {
  const alg = joseToCose.get(jwk.alg)
  if (!alg) {
    throw new Error('This library requires verification keys contain fully specified algorithms')
  }
  return alg
}

export default getAlgFromVerificationKey