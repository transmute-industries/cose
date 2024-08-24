import { calculateJwkThumbprint, calculateJwkThumbprintUri, base64url } from "jose";

import { encodeCanonical } from "../../cbor";

import subtleCryptoProvider from "../../crypto/subtleCryptoProvider";
import { EC2, Key, KeyTypes } from "../Params";
import { CoseKey } from ".";

// https://www.ietf.org/archive/id/draft-ietf-cose-key-thumbprint-01.html#section-6
const calculateCoseKeyThumbprint = async (coseKey: CoseKey): Promise<ArrayBuffer> => {
  if (coseKey.get(Key.Kty) !== KeyTypes.EC2) {
    throw new Error('Unsupported key type (Only EC2 are supported')
  }
  const onlyRequiredMap = new Map()
  const requiredKeys = [EC2.Kty, EC2.Crv, EC2.X, EC2.Y]
  for (const [key, value] of coseKey.entries()) {
    if (requiredKeys.includes(key as number)) {
      onlyRequiredMap.set(key, value)
    }
  }
  const encoded = encodeCanonical(onlyRequiredMap)
  const subtle = await subtleCryptoProvider()
  const digest = subtle.digest("SHA-256", encoded)
  return digest
}

const calculateCoseKeyThumbprintUri = async (coseKey: CoseKey): Promise<string> => {
  const prefix = `urn:ietf:params:oauth:ckt:sha-256`
  const digest = await calculateCoseKeyThumbprint(coseKey)
  return `${prefix}:${base64url.encode(new Uint8Array(digest))}`
}

export const thumbprint = {
  calculateJwkThumbprint,
  calculateJwkThumbprintUri,
  calculateCoseKeyThumbprint,
  calculateCoseKeyThumbprintUri,
  uri: calculateCoseKeyThumbprintUri
}