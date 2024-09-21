

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose"


export type CoseKeyAgreementAlgorithms = 'ECDH-ES+A128KW'
export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512' | 'ESP256' | 'ESP384'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'
import { thumbprint } from "./thumbprint"
import { formatJwk } from './formatJwk'

import { less_specified } from "../../iana/requested/cose"
import * as cose from "../../iana/assignments/cose"

export const generate = async <T>(alg: CoseSignatureAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json'): Promise<T> => {
  const cryptoKeyPair = await generateKeyPair(
    less_specified[alg],
    { extractable: true }
  );
  const privateKeyJwk = await exportJWK(cryptoKeyPair.privateKey)
  const jwkThumbprint = await calculateJwkThumbprint(privateKeyJwk)
  privateKeyJwk.kid = jwkThumbprint
  privateKeyJwk.alg = alg
  if (contentType === 'application/jwk+json') {
    return formatJwk(privateKeyJwk) as T
  }
  if (contentType === 'application/cose-key') {
    delete privateKeyJwk.kid;
    const privateKeyCoseKey = await convertJsonWebKeyToCoseKey<cose.any_cose_key>(privateKeyJwk)
    const coseKeyThumbprint = await thumbprint.calculateCoseKeyThumbprint(privateKeyCoseKey)
    privateKeyCoseKey.set(cose.ec2.kid, coseKeyThumbprint)
    return privateKeyCoseKey as T
  }
  throw new Error('Unsupported content type.')
}



