import { CoseKey } from ".";
import { PrivateKeyJwk } from "../sign1";


export const extractPublicKeyJwk = (privateKeyJwk: PrivateKeyJwk) => {
  if (privateKeyJwk.kty !== 'EC') {
    throw new Error('Only EC keys are supported')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, key_ops, ...publicKeyJwk } = privateKeyJwk
  return publicKeyJwk
}

export const extractPublicCoseKey = (secretKey: CoseKey) => {
  const publicCoseKeyMap = new Map(secretKey)
  if (publicCoseKeyMap.get(1) !== 2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!publicCoseKeyMap.get(-4)) {
    throw new Error('privateKey is not a secret / private key (has no d / -4)')
  }
  publicCoseKeyMap.delete(-4);
  return publicCoseKeyMap
}

export const publicFromPrivate = <T>(secretKey: PrivateKeyJwk | CoseKey) => {
  if ((secretKey as any).kty) {
    return extractPublicKeyJwk(secretKey as PrivateKeyJwk) as T
  }
  return extractPublicCoseKey(secretKey as CoseKey) as T
}