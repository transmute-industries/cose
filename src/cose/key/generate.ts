

import { generateKeyPair, exportJWK, calculateJwkThumbprint, JWK } from "jose"

import { IANACOSEAlgorithms } from "../algorithms"

export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'

export const generate = async (alg: CoseSignatureAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json') => {
  const knownAlgorithm = Object.values(IANACOSEAlgorithms).find((
    entry
  ) => {
    return entry.Name === alg
  })

  if (!knownAlgorithm) {
    throw new Error('Algorithm is not supported.')
  }

  const cryptoKeyPair = await generateKeyPair(knownAlgorithm.Name, { extractable: true });
  const secretKeyJwk = await exportJWK(cryptoKeyPair.privateKey)
  const jwkThumbprint = await calculateJwkThumbprint(secretKeyJwk)
  secretKeyJwk.kid = jwkThumbprint

  if (contentType === 'application/jwk+json') {
    return secretKeyJwk as JWK
  }

  if (contentType === 'application/cose-key') {
    return convertJsonWebKeyToCoseKey(secretKeyJwk)
  }



}



