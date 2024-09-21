
import * as cose from "../../iana/assignments/cose";

import { PrivateKeyJwk } from "../sign1";



export const extractPublicKeyJwk = (privateKeyJwk: PrivateKeyJwk) => {
  if (privateKeyJwk.kty !== 'EC') {
    throw new Error('Only EC keys are supported')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, key_ops, ...publicKeyJwk } = privateKeyJwk
  return publicKeyJwk
}

export const extractPublicCoseKey = <T extends cose.any_cose_key | cose.ec2_key>(privateKey: cose.any_cose_key) => {
  const publicCoseKeyMap = new Map(privateKey)
  if (publicCoseKeyMap.get(cose.cose_key.kty) !== cose.cose_key_type.ec2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!publicCoseKeyMap.get(cose.ec2.d)) {
    throw new Error('privateKey is not a secret / private key (has no d / -4)')
  }
  publicCoseKeyMap.delete(cose.ec2.d);
  return publicCoseKeyMap as T
}

export const publicFromPrivate = <T>(privateKey: PrivateKeyJwk | cose.any_cose_key) => {
  if ((privateKey as PrivateKeyJwk).kty) {
    return extractPublicKeyJwk(privateKey as PrivateKeyJwk) as T
  }
  return extractPublicCoseKey(privateKey as cose.any_cose_key) as T
}