import { suites, JOSE_HPKE_ALG } from "./suites"
import subtle from '../../../crypto/subtleCryptoProvider'
import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"



import { encode } from 'cbor-web';

export const computeHPKEAad = (protectedHeader: any, protectedRecipientHeader?: any) => {
  if (protectedRecipientHeader) {
    // not sure what to do when recipient protected header exists...
    return encode([protectedHeader, protectedRecipientHeader])
  }
  return protectedHeader
}

export type JWK = {
  kid?: string
  alg?: string
  kty: string
  crv: string
}

export const isKeyAlgorithmSupported = (recipient: JWK) => {
  const supported_alg = Object.keys(suites) as string[]
  return supported_alg.includes(`${recipient.alg}`)
}

export const formatJWK = (jwk: any) => {
  const { kid, alg, kty, crv, x, y, d } = jwk
  return JSON.parse(JSON.stringify({
    kid, alg, kty, crv, x, y, d
  }))
}

export const publicFromPrivate = (privateKeyJwk: any) => {
  const { kid, alg, kty, crv, x, y, ...rest } = privateKeyJwk
  return {
    kid, alg, kty, crv, x, y
  }
}

export const publicKeyFromJwk = async (publicKeyJwk: any) => {
  const api = (await subtle())
  const publicKey = await api.importKey(
    'jwk',
    publicKeyJwk,
    {
      name: 'ECDH',
      namedCurve: publicKeyJwk.crv,
    },
    true,
    [],
  )
  return publicKey;
}

export const privateKeyFromJwk = async (privateKeyJwk: any) => {
  const api = (await subtle())
  const privateKey = await api.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: privateKeyJwk.crv,
    },
    true,
    ['deriveBits', 'deriveKey'],
  )
  return privateKey
}

export const generate = async (alg: JOSE_HPKE_ALG) => {
  if (!suites[alg]) {
    throw new Error('Algorithm not supported')
  }
  let kp;
  if (alg.includes('P256')) {
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256', extractable: true })
  } else if (alg.includes('P384')) {
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-384', extractable: true })
  } else {
    throw new Error('Could not generate private key for ' + alg)
  }
  const privateKeyJwk = await exportJWK(kp.privateKey);
  privateKeyJwk.kid = await calculateJwkThumbprintUri(privateKeyJwk)
  privateKeyJwk.alg = alg;
  return formatJWK(privateKeyJwk)
}
