import { calculateJwkThumbprint, calculateJwkThumbprintUri, base64url, JWK } from "jose";

import { encodeCanonical } from "../../cbor";

import subtleCryptoProvider from "../../crypto/subtle";
import * as cose from '../../iana/assignments/cose'
import { web_key_type } from "../../iana/assignments/jose";

export type cose_key_thumbprint = Uint8Array
export type cose_key_thumbprint_base_encoded = string
export type cose_key_thumbprint_uri = `urn:ietf:params:oauth:ckt:sha-256:${cose_key_thumbprint_base_encoded}`

export type web_key_thumbprint = string
export type web_key_thumbprint_uri = `urn:ietf:params:oauth:jwk-thumbprint:${web_key_thumbprint}`

// https://www.ietf.org/archive/id/draft-ietf-cose-key-thumbprint-01.html#section-6
const cose_key_thumbprint = async (coseKey: cose.any_cose_key): Promise<cose_key_thumbprint> => {
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
  const digest = await subtle.digest("SHA-256", encoded)
  return new Uint8Array(digest)
}

export const cose_key_thumbprint_uri = async (coseKey: cose.any_cose_key): Promise<cose_key_thumbprint_uri> => {
  const prefix = `urn:ietf:params:oauth:ckt:sha-256`
  const digest = await cose_key_thumbprint(coseKey)
  return `${prefix}:${base64url.encode(new Uint8Array(digest))}`
}

export const web_key_thumbprint = async (jwk: web_key_type): Promise<web_key_thumbprint> => {
  return calculateJwkThumbprint(jwk as JWK)
}

export const web_key_thumbprint_uri = async (jwk: web_key_type): Promise<web_key_thumbprint_uri> => {
  return calculateJwkThumbprintUri(jwk as JWK) as Promise<web_key_thumbprint_uri>
}