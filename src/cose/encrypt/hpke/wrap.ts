
import { createAAD } from '../utils'

import { COSE_Encrypt, COSE_Encrypt0, Direct, Protected, Unprotected, UnprotectedHeader } from '../../Params'

import { RequestWrapDecryption, RequestWrapEncryption, RequestDirectEncryption, RequestDirectDecryption } from '../types'
import { EMPTY_BUFFER } from "../../../cbor"

import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

import { computeInfo } from './computeInfo'

export type JOSE_HPKE_ALG = `HPKE-Base-P256-SHA256-AES128GCM` | `HPKE-Base-P384-SHA256-AES128GCM`
import subtle from '../../../crypto/subtleCryptoProvider'

import * as aes from '../aes'
import { encode } from 'cbor-web';

import { toArrayBuffer } from '../../../cbor'

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

export const suites = {
  ['HPKE-Base-P256-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
  ['HPKE-Base-P384-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP384HkdfSha384,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
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

export const primaryAlgorithm = {
  'label': `HPKE-Base-P256-SHA256-AES128GCM`,
  'value': 35
}

export const secondaryAlgorithm = {
  'label': `HPKE-Base-P384-SHA384-AES256GCM`,
  'value': 37
}



const computeHPKEAad = (protectedHeader: any, protectedRecipientHeader?: any) => {
  if (protectedRecipientHeader) {
    // not sure what to do when recipient protected header exists...
    return encode([protectedHeader, protectedRecipientHeader])
  }
  return protectedHeader
}

export const encryptWrap = async (req: RequestWrapEncryption) => {
  if (req.unprotectedHeader === undefined) {
    req.unprotectedHeader = UnprotectedHeader([])
  }
  const alg = req.protectedHeader.get(1)
  if (alg !== 1) {
    throw new Error('Only A128GCM is supported at this time')
  }
  const unprotectedHeader = req.unprotectedHeader;
  const encodedProtectedHeader = encode(req.protectedHeader)
  const cek = await aes.generateKey(alg);
  const iv = await aes.getIv(alg);
  unprotectedHeader.set(5, iv); // set IV
  const senderRecipients = []
  for (const recipient of req.recipients.keys) {
    const suite = suites[recipient.alg as JOSE_HPKE_ALG]
    const recipientProtectedHeader = new Map([[
      1, 35
    ]])
    const encodedRecipientProtectedHeader = encode(recipientProtectedHeader)
    const info = await computeInfo(recipientProtectedHeader)
    const sender = await suite.createSenderContext({
      info,
      recipientPublicKey: await publicKeyFromJwk(recipient),
    });
    const hpkeSealAad = computeHPKEAad(encodedProtectedHeader, encodedRecipientProtectedHeader)
    const encryptedKey = await sender.seal(cek, hpkeSealAad)
    const encapsulatedKey = Buffer.from(sender.enc);
    // commented out the approach in JOSE HPKE
    // const recipientCoseKey = new Map<any, any>([
    //   [1, 5], // kty: EK
    //   [- 1, encapsulatedKey]
    // ])
    const recipientUnprotectedHeader = new Map([
      [4, recipient.kid], // kid
      // [-1, recipientCoseKey], // epk
      [-4, encapsulatedKey]
    ])
    senderRecipients.push([
      encodedRecipientProtectedHeader,
      recipientUnprotectedHeader,
      encryptedKey
    ])
  }
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(encodedProtectedHeader, 'Encrypt', externalAad)
  const ciphertext = await aes.encrypt(
    alg,
    new Uint8Array(req.plaintext),
    new Uint8Array(iv),
    new Uint8Array(aad),
    new Uint8Array(cek)
  )
  return encodeAsync(new Tagged(COSE_Encrypt, [
    encodedProtectedHeader,
    unprotectedHeader,
    ciphertext,
    senderRecipients
  ]), { canonical: true })
}

export const decryptWrap = async (req: RequestWrapDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== COSE_Encrypt) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  const [recipient] = recipients

  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  const kid = recipientUnprotectedHeader.get(Unprotected.Kid).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  const decodedRecipientProtectedHeader = await decodeFirst(recipientProtectedHeader)
  // comment out approach in jose hpke
  // const epk = recipientUnprotectedHeader.get(-1)
  // // ensure the epk has the algorithm that is set in the protected header
  // const recipientAlgorithm = decodedRecipientProtectedHeader.get(1)
  // epk.set(3, recipientAlgorithm) // EPK is allowed to have an alg
  const ek = recipientUnprotectedHeader.get(Unprotected.Ek)
  const suite = suites[receiverPrivateKeyJwk.alg as JOSE_HPKE_ALG]
  const info = await computeInfo(decodedRecipientProtectedHeader)
  const hpkeRecipient = await suite.createRecipientContext({
    info,
    recipientKey: await privateKeyFromJwk(receiverPrivateKeyJwk),
    // enc: epk.get(-1) // ek
    enc: ek
  })
  const hpkeSealAad = computeHPKEAad(protectedHeader, recipientProtectedHeader)
  const contentEncryptionKey = await hpkeRecipient.open(recipientCipherText, hpkeSealAad)
  const iv = unprotectedHeader.get(Unprotected.Iv)
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(Protected.Alg)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(contentEncryptionKey))
}
