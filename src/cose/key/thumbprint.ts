import { calculateJwkThumbprint, calculateJwkThumbprintUri, base64url } from "jose";

import { encodeCanonical } from "../../cbor";

import subtleCryptoProvider from "../../crypto/subtleCryptoProvider";
import * as cose from '../../iana/assignments/cose'

// https://www.ietf.org/archive/id/draft-ietf-cose-key-thumbprint-01.html#section-6
const calculateCoseKeyThumbprint = async (coseKey: cose.any_cose_key): Promise<ArrayBuffer> => {
  if (coseKey.get(cose.cose_key.kty) !== cose.cose_key_type.ec2) {
    throw new Error('Unsupported key type (Only EC2 are supported')
  }
  const onlyRequiredMap = new Map()
  const requiredKeys = [cose.ec2.kty, cose.ec2.crv, cose.ec2.x, cose.ec2.y]
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

const calculateCoseKeyThumbprintUri = async (coseKey: cose.any_cose_key): Promise<string> => {
  const prefix = `urn:ietf:params:oauth:ckt:sha-256`
  const digest = await calculateCoseKeyThumbprint(coseKey)
  return `${prefix}:${base64url.encode(new Uint8Array(digest))}`
}

export const thumbprint = {
  calculateJwkThumbprint,
  calculateJwkThumbprintUri,
  calculateCoseKeyThumbprint,
  calculateCoseKeyThumbprintUri,
}