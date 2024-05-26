

import { ml_kem768 } from '@noble/post-quantum/ml-kem';

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose"

import { IANACOSEAlgorithms } from "../algorithms"


import { CoseKey } from '.'
export type CoseKeyAgreementAlgorithms = 'ECDH-ES+A128KW'
export type CoseDirectEncryptionAlgorithms = 'HPKE-Base-P256-SHA256-AES128GCM' | 'HPKE-Base-ML-KEM-768-SHA256-AES128GCM'
export type CoseSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'
export type ContentTypeOfJsonWebKey = 'application/jwk+json'
export type ContentTypeOfCoseKey = 'application/cose-key'
export type PrivateKeyContentType = ContentTypeOfCoseKey | ContentTypeOfJsonWebKey

import { convertJsonWebKeyToCoseKey } from './convertJsonWebKeyToCoseKey'

import { thumbprint } from "./thumbprint"

import { formatJwk } from './formatJwk'
import { cbor } from "../.."

import { Key, KeyType, KeyTypeAlgorithms, KeyTypeParameters } from '../..';
import { toArrayBuffer } from '../../cbor';

export const generate = async <T>(alg: CoseSignatureAlgorithms | CoseDirectEncryptionAlgorithms, contentType: PrivateKeyContentType = 'application/jwk+json'): Promise<T> => {
  let knownAlgorithm = Object.values(IANACOSEAlgorithms).find((
    entry
  ) => {
    return entry.Name === alg
  }) as any
  if (alg === 'HPKE-Base-ML-KEM-768-SHA256-AES128GCM') {
    const keys = ml_kem768.keygen();
    // {                                   / COSE Key                /
    //   1: -666666,                       / ML-KEM Key Type         /
    //   3: -777777,                       / ML-KEM-768 Algorithm    /
    //   -13: h'7803c0f9...3f6e2c70',      / ML-KEM Private Key      /
    //   -14: h'7803c0f9...3bba7abd',      / ML-KEM Public Key       /
    // }
    return new Map<number, number | ArrayBuffer>([
      [Key.Type, KeyType['ML-KEM']],
      [Key.Algorithm, KeyTypeAlgorithms['ML-KEM']['ML-KEM-768']],
      [KeyTypeParameters['ML-KEM'].Public, toArrayBuffer(keys.publicKey)],
      [KeyTypeParameters['ML-KEM'].Secret, toArrayBuffer(keys.secretKey)]
    ]) as T
  }
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
    if (alg === 'HPKE-Base-P256-SHA256-AES128GCM') {
      return new Uint8Array(cbor.encode(secretKeyCoseKey)) as T
    }
    return secretKeyCoseKey as T
  }
  throw new Error('Unsupported content type.')
}



