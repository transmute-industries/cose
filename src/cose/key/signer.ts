import { CoseKey } from ".";

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { toArrayBuffer } from "../../cbor";

export const signer = (secretKey: CoseKey) => {
  const alg = secretKey.get(3);
  if (alg === -49) {
    return {
      sign: async (bytes: ArrayBuffer) => {
        return toArrayBuffer(ml_dsa65.sign(new Uint8Array(secretKey.get(-2) as ArrayBuffer), new Uint8Array(bytes)))
      }
    }
  }
  throw new Error('Unsupported algorithm')
}