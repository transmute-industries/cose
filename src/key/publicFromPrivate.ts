import { PrivateCoseKeyMap, PublicCoseKeyMap } from "./types";

export const publicFromPrivate = (secretCoseKeyMap: PrivateCoseKeyMap): PublicCoseKeyMap => {
  if (secretCoseKeyMap.get(1) !== 2) {
    throw new Error('Only EC2 keys are supported')
  }
  if (!secretCoseKeyMap.get(-4)) {
    throw new Error('secretCoseKeyMap is not a secret / private key (has no d / -4)')
  }
  secretCoseKeyMap.delete(-4);
  return secretCoseKeyMap
}