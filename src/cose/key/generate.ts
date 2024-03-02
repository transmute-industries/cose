

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose"

import { IANACOSEAlgorithms } from "../algorithms"


import { CoseKey } from '.'
export type CoseKeyAgreementAlgorithms = 'ECDH-ES+A128KW'
export type CoseDirectEncryptionAlgorithms = 'HPKE-Base-P256-SHA256-AES128GCM'
export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'

import { thumbprint } from "./thumbprint"

import { formatJwk } from './formatJwk'


export const generate = async <T>(alg: CoseSignatureAlgorithms | CoseDirectEncryptionAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json'): Promise<T> => {
  let knownAlgorithm = Object.values(IANACOSEAlgorithms).find((
    entry
  ) => {
    return entry.Name === alg
  }) as any
  if (alg === 'HPKE-Base-P256-SHA256-AES128GCM') {
    knownAlgorithm = {
      Name: 'ECDH-ES+A128KW',
      Curve: 'P-256'
    }
  }
  if (!knownAlgorithm) {
    throw new Error('Algorithm is not supported.')
  }
  const cryptoKeyPair = await generateKeyPair(knownAlgorithm.Name, { extractable: true, crv: knownAlgorithm.Curve });
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



