

import { COSE_Encrypt0, Direct, Protected, Unprotected, UnprotectedHeader } from '../../Params'
import { RequestDirectEncryption, RequestDirectDecryption } from '../types'
import { Tagged, decodeFirst, encodeAsync } from "cbor-web"
import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

export type JOSE_HPKE_ALG = `HPKE-Base-P256-SHA256-AES128GCM` | `HPKE-Base-P384-SHA256-AES128GCM`
import subtle from '../../../crypto/subtleCryptoProvider'
import { computeInfo } from './computeInfo'
import { suites } from './suites'
import { encode } from 'cbor-web';
export type JWK = {
  kid?: string
  alg?: string
  kty: string
  crv: string
}

export type JWKS = {
  keys: JWK[]
}

export type HPKERecipient = {
  encrypted_key: string
  header: {
    kid?: string
    alg?: string
    epk?: JWK
    encapsulated_key: string,
  }
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



const computeHPKEAad = (protectedHeader: any, protectedRecipientHeader?: any) => {
  if (protectedRecipientHeader) {
    // not sure what to do when recipient protected header exists...
    return encode([protectedHeader, protectedRecipientHeader])
  }
  return protectedHeader
}

export const encryptDirect = async (req: RequestDirectEncryption) => {
  if (req.unprotectedHeader === undefined) {
    req.unprotectedHeader = UnprotectedHeader([])
  }
  const alg = req.protectedHeader.get(Protected.Alg)
  if (alg !== Direct['HPKE-Base-P256-SHA256-AES128GCM']) {
    throw new Error('Only alg 35 is supported')
  }
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader;
  const [recipientPublicKeyJwk] = req.recipients.keys
  const suite = suites[recipientPublicKeyJwk.alg as JOSE_HPKE_ALG]
  const info = await computeInfo(req.protectedHeader)
  const sender = await suite.createSenderContext({
    info,
    recipientPublicKey: await publicKeyFromJwk(recipientPublicKeyJwk),
  });
  // No way to use external aad here?
  const hpkeSealAad = computeHPKEAad(protectedHeader)
  const ciphertext = await sender.seal(req.plaintext, hpkeSealAad)
  // comments out the approach used in jose hpke
  // const recipientCoseKey = new Map<any, any>([
  //   [1, 5], // kty: EK
  //   [- 1, sender.enc]
  // ])
  unprotectedHeader.set(Unprotected.Kid, recipientPublicKeyJwk.kid)
  // unprotectedHeader.set(-1, recipientCoseKey)
  unprotectedHeader.set(Unprotected.Ek, sender.enc)
  return encodeAsync(new Tagged(COSE_Encrypt0, [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
  ]), { canonical: true })
}

export const decryptDirect = async (req: RequestDirectDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== COSE_Encrypt0) {
    throw new Error('Only tag 16 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext] = decoded.value
  const kid = unprotectedHeader.get(Unprotected.Kid).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const ek = unprotectedHeader.get(Unprotected.Ek)
  // const epk = unprotectedHeader.get(-1)
  // // ensure the epk has the algorithm that is set in the protected header
  // const recipientAlgorithm = unprotectedHeader.get(1)
  // epk.set(3, recipientAlgorithm) // EPK is allowed to have an alg
  const suite = suites[receiverPrivateKeyJwk.alg as JOSE_HPKE_ALG]
  const info = await computeInfo(decodedProtectedHeader)
  const hpkeRecipient = await suite.createRecipientContext({
    info,
    recipientKey: await privateKeyFromJwk(receiverPrivateKeyJwk),
    // enc: epk.get(-1) // ek
    enc: ek
  })
  // No way to user external aad here?
  const hpkeSealAad = computeHPKEAad(protectedHeader)
  const plaintext = await hpkeRecipient.open(ciphertext, hpkeSealAad)
  return plaintext
}
