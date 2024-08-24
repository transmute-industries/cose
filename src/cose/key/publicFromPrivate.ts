import { CoseKey } from ".";
import { EC2, Key, KeyTypes } from "../Params";
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
  if (publicCoseKeyMap.get(Key.Kty) !== KeyTypes.EC2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!publicCoseKeyMap.get(EC2.D)) {
    throw new Error('privateKey is not a secret / private key (has no d / -4)')
  }
  publicCoseKeyMap.delete(EC2.D);
  return publicCoseKeyMap
}

export const publicFromPrivate = <T>(secretKey: PrivateKeyJwk | CoseKey) => {
  if ((secretKey as PrivateKeyJwk).kty) {
    return extractPublicKeyJwk(secretKey as PrivateKeyJwk) as T
  }
  return extractPublicCoseKey(secretKey as CoseKey) as T
}