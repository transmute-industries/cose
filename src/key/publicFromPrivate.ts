import { SecretCoseKeyMap, PublicCoseKeyMap } from "./types";

export const publicFromPrivate = (secretCoseKeyMap: SecretCoseKeyMap): PublicCoseKeyMap => {
  const publicCoseKeyMap = new Map(secretCoseKeyMap)
  if (publicCoseKeyMap.get(1) !== 2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!publicCoseKeyMap.get(-4)) {
    throw new Error('secretCoseKeyMap is not a secret / private key (has no d / -4)')
  }
  publicCoseKeyMap.delete(-4);
  return publicCoseKeyMap
}