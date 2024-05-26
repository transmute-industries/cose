import { calculateJwkThumbprint, calculateJwkThumbprintUri, base64url } from "jose";

import { encodeCanonical } from "../../cbor";

import subtleCryptoProvider from "../../crypto/subtleCryptoProvider";

import { Key, KeyType, KeyTypeParameters } from '../Params'

// https://www.ietf.org/archive/id/draft-ietf-cose-key-thumbprint-01.html#section-6
const calculateCoseKeyThumbprint = async (coseKey: Map<any, any>): Promise<ArrayBuffer> => {
  const onlyRequiredMap = new Map()
  const requriedKeys = [Key.Type]
  if (coseKey.get(Key.Type) === KeyType.EC2) {
    requriedKeys.push(KeyTypeParameters['EC2'].Curve)
    requriedKeys.push(KeyTypeParameters['EC2'].PublicX)
    requriedKeys.push(KeyTypeParameters['EC2'].PublicY)
  }
  if (coseKey.get(Key.Type) === KeyType["ML-KEM"]) {
    requriedKeys.push(KeyTypeParameters['ML-KEM'].Public)
  }
  for (const [key, value] of coseKey.entries()) {
    if (requriedKeys.includes(key as number)) {
      onlyRequiredMap.set(key, value)
    }
  }
  const encoded = encodeCanonical(onlyRequiredMap)
  const subtle = await subtleCryptoProvider()
  const digest = subtle.digest("SHA-256", encoded)
  return digest
}

const calculateCoseKeyThumbprintUri = async (coseKey: Map<any, any>): Promise<string> => {
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