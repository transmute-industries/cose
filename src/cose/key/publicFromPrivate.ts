
import { any_cose_key, ec2_key } from "../../iana/assignments/cose";
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

export const extractPublicCoseKey = <T extends any_cose_key | ec2_key>(privateKey: any_cose_key) => {
  const publicCoseKeyMap = new Map(privateKey)
  if (publicCoseKeyMap.get(Key.Kty) !== KeyTypes.EC2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!publicCoseKeyMap.get(EC2.D)) {
    throw new Error('privateKey is not a secret / private key (has no d / -4)')
  }
  publicCoseKeyMap.delete(EC2.D);
  return publicCoseKeyMap as T
}

export const publicFromPrivate = <T>(privateKey: PrivateKeyJwk | any_cose_key) => {
  if ((privateKey as PrivateKeyJwk).kty) {
    return extractPublicKeyJwk(privateKey as PrivateKeyJwk) as T
  }
  return extractPublicCoseKey(privateKey as any_cose_key) as T
}