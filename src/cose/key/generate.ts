

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose"

import { IANACOSEAlgorithms } from "../algorithms"


import { CoseKey } from '.'
export type CoseKeyAgreementAlgorithms = 'ECDH-ES+A128KW'
export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512' | 'ML-DSA-65'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'

import { thumbprint } from "./thumbprint"

import { formatJwk } from './formatJwk'


import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { randomBytes } from "@noble/post-quantum/utils"
import { toArrayBuffer } from "../../cbor"


export const generate = async <T>(alg: CoseSignatureAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json'): Promise<T> => {
  const knownAlgorithm = Object.values(IANACOSEAlgorithms).find((
    entry
  ) => {
    return entry.Name === alg
  })
  if (alg === 'ML-DSA-65') {
    const seed = randomBytes(32)
    const keys = ml_dsa65.keygen(seed);
    return new Map<any, any>([
      [1, 7],    // kty : ML-DSA
      [3, -49],  // alg : ML-DSA-65
      [-1, toArrayBuffer(keys.publicKey)], // public key
      [-2, toArrayBuffer(keys.secretKey)], // secret key
    ]) as T
  }
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
    const secretKeyCoseKey = await convertJsonWebKeyToCoseKey<CoseKey>(secretKeyJwk)
    const coseKeyThumbprint = await thumbprint.calculateCoseKeyThumbprint(secretKeyCoseKey)
    secretKeyCoseKey.set(2, coseKeyThumbprint)
    return secretKeyCoseKey as T
  }
  throw new Error('Unsupported content type.')
}



