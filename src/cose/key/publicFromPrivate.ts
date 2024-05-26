import { CoseKey } from ".";
import { Key, KeyType, KeyTypeParameters } from "../Params";
import { SecretKeyJwk } from "../sign1";


export const extracePublicKeyJwk = (secretKeyJwk: SecretKeyJwk) => {
  if (['EC'].includes(secretKeyJwk.kty || '')) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, p, q, dp, dq, qi, key_ops, ...publicKeyJwk } = secretKeyJwk
    return publicKeyJwk
  }

  throw new Error('Unsupported json web key type')

}

export const extractPublicCoseKey = (secretKey: CoseKey) => {
  const publicCoseKeyMap = new Map(secretKey)
  if (publicCoseKeyMap.get(Key.Type) === KeyType.EC2) {
    if (!publicCoseKeyMap.get(KeyTypeParameters['EC2'].Secret)) {
      throw new Error('No secret component found for EC2 key, not a secret key.')
    }
    publicCoseKeyMap.delete(KeyTypeParameters['EC2'].Secret);
    return publicCoseKeyMap
  }

  if (publicCoseKeyMap.get(Key.Type) === KeyType["ML-KEM"]) {
    if (!publicCoseKeyMap.get(KeyTypeParameters['ML-KEM'].Secret)) {
      throw new Error('No secret component found for ML-KEM key, not a secret key.')
    }
    publicCoseKeyMap.delete(KeyTypeParameters['ML-KEM'].Secret);
    return publicCoseKeyMap
  }

  throw new Error('Unsupported cose key type')
}

export const publicFromPrivate = <T>(secretKey: SecretKeyJwk | CoseKey) => {
  if ((secretKey as any).kty) {
    return extracePublicKeyJwk(secretKey as SecretKeyJwk) as T
  }
  return extractPublicCoseKey(secretKey as CoseKey) as T
}