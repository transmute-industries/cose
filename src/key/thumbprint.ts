import { calculateJwkThumbprint, calculateJwkThumbprintUri, base64url } from "jose";
import { CoseKeyMap } from "./types";
import cbor from "../cbor";

import subtleCryptoProvider from "../lib/subtleCryptoProvider";

// https://www.ietf.org/archive/id/draft-ietf-cose-key-thumbprint-01.html#section-6
const calculateCoseKeyThumbprint = async (coseKey: CoseKeyMap): Promise<ArrayBuffer> => {
  const onlyRequiredMap = new Map()
  const requriedKeys = [1, -1, -2, -3]
  for (const [key, value] of coseKey.entries()) {
    if (requriedKeys.includes(key as number)) {
      onlyRequiredMap.set(key, value)
    }
  }
  const encoded = cbor.web.encodeCanonical(onlyRequiredMap)
  const subtle = await subtleCryptoProvider()
  const digest = subtle.digest("SHA-256", encoded)
  return digest
}

const calculateCoseKeyThumbprintUri = async (coseKey: CoseKeyMap): Promise<string> => {
  const prefix = `urn:ietf:params:oauth:ckt:sha-256`
  const digest = await calculateCoseKeyThumbprint(coseKey)
  return `${prefix}:${base64url.encode(new Uint8Array(digest))}`
}

export const thumbprint = {
  calculateJwkThumbprint,
  calculateJwkThumbprintUri,
  calculateCoseKeyThumbprint,
  calculateCoseKeyThumbprintUri
}

export default thumbprint