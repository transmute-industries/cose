

import { generateKeyPair, exportJWK, calculateJwkThumbprint, JWK } from "jose"

import { IANACOSEAlgorithms } from "../algorithms"

export type CoseKeyAgreementAlgorithms = 'ECDH-ES+A128KW'
export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'

import { thumbprint } from "./thumbprint"

import { formatJwk } from './formatJwk'


import { getRecommendedAlgorithmForCoseKey } from './getRecommendedAlgorithmForCoseKey'
export const generate = async <T>(alg: CoseSignatureAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json'): Promise<T> => {
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
  secretKeyJwk.alg = alg
  if (contentType === 'application/jwk+json') {
    return formatJwk(secretKeyJwk) as T
  }
  if (contentType === 'application/cose-key') {
    delete secretKeyJwk.kid;
    const secretKeyCoseKey = convertJsonWebKeyToCoseKey(secretKeyJwk)
    const coseKeyThumbprint = await thumbprint.calculateCoseKeyThumbprint(secretKeyCoseKey)
    secretKeyCoseKey.set(2, coseKeyThumbprint)
    return secretKeyCoseKey as T
  }
  throw new Error('Unsupported content type.')
}



