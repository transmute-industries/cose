import { CoseKey } from "../..";

export const getRecommendedAlgorithmForCoseKey = (coseKey: CoseKey, use: 'sig' | 'enc'): number => {
  const alg = coseKey.get(2)
  if (alg) {
    return alg as number
  }
  if (use === 'sig') {
    return -7 // ES256
  }
  if (use === 'enc') {
    return -29 // ECDH-ES + A128KW
  }
  throw new Error('Unable to recommend an algorithm')
}