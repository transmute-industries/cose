
import { createAAD, COSE_Encrypt_Tag, RequestWrapDecryption, RequestWrapEncryption, RequestDirectEncryption, RequestDirectDecryption } from './utils'
import { EMPTY_BUFFER } from "../../cbor"

import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import crypto from 'crypto';

import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export type JOSE_HPKE_ALG = `HPKE-Base-P256-SHA256-AES128GCM` | `HPKE-Base-P384-SHA256-AES128GCM`


import * as aes from './aes'
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
  const publicKey = await crypto.subtle.importKey(
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
  const privateKey = await crypto.subtle.importKey(
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


const keyLength = {
  '35': 16, // ...AES128GCM
} as Record<number | string, number>;


type PartyInfo = [Buffer | null, Buffer | number | null, Buffer | null]

const compute_PartyInfo = (identity: Buffer | null, nonce: Buffer | number | null, other: Buffer | null) => {
  return [
    identity || null, // identity
    nonce || null, // nonce
    other || null // other
  ] as PartyInfo
}

// https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.2
const compute_COSE_KDF_Context = (
  AlgorithmID: number,
  PartyUInfo: PartyInfo,
  PartyVInfo: PartyInfo,
  Protected: Buffer,
  SuppPrivInfo?: Buffer
) => {
  const info = [
    AlgorithmID, // AlgorithmID
    PartyUInfo,
    PartyVInfo,
    [ // SuppPubInfo
      keyLength[`${AlgorithmID}`] * 8, // keyDataLength
      Protected
    ]
  ]
  if (SuppPrivInfo) {
    (info as any).push(SuppPrivInfo)
  }
  return encodeAsync(info);
}

const computeHPKEAad = (protectedHeader: any, protectedRecipientHeader?: any) => {
  if (protectedRecipientHeader) {
    // not sure what to do when recipient protected header exists...
    return encode([protectedHeader, protectedRecipientHeader])
  }
  return protectedHeader
}

const encryptWrap = async (req: RequestWrapEncryption) => {
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
    const recipientCoseKey = new Map<any, any>([
      [1, 5], // kty: EK
      [- 1, encapsulatedKey]
    ])
    const recipientUnprotectedHeader = new Map([
      [4, recipient.kid], // kid
      [-1, recipientCoseKey], // epk
    ])
    senderRecipients.push([
      encodedRecipientProtectedHeader,
      recipientUnprotectedHeader,
      encryptedKey
    ])
  }
  const aad = await createAAD(encodedProtectedHeader, 'Encrypt', EMPTY_BUFFER)
  const ciphertext = await aes.encrypt(
    alg,
    new Uint8Array(req.plaintext),
    new Uint8Array(iv),
    new Uint8Array(aad),
    new Uint8Array(cek)
  )
  const COSE_Encrypt = [
    encodedProtectedHeader,
    unprotectedHeader,
    ciphertext,
    senderRecipients
  ]
  return encodeAsync(new Tagged(COSE_Encrypt_Tag, COSE_Encrypt), { canonical: true })
}

const computeInfo = async (protectedHeader: Map<any, any>) => {
  let info = undefined;
  const algorithmId = protectedHeader.get(1)
  const partyUIdentity = protectedHeader.get(-21) || null
  const partyUNonce = protectedHeader.get(-22) || null
  const partyUOther = protectedHeader.get(-23) || null
  const partyVIdentity = protectedHeader.get(-24) || null
  const partyVNonce = protectedHeader.get(-25) || null
  const partyVOther = protectedHeader.get(-26) || null
  if (partyUNonce || partyVNonce) {
    info = await compute_COSE_KDF_Context(
      algorithmId,
      compute_PartyInfo(partyUIdentity, partyUNonce, partyUOther),
      compute_PartyInfo(partyVIdentity, partyVNonce, partyVOther),
      await encodeAsync(protectedHeader),
    )
  }
  return info
}

export const encryptDirect = async (req: RequestDirectEncryption) => {
  const alg = req.protectedHeader.get(1)
  if (alg !== 35) {
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
  const hpkeSealAad = computeHPKEAad(protectedHeader)
  const ciphertext = await sender.seal(req.plaintext, hpkeSealAad)
  const recipientCoseKey = new Map<any, any>([
    [1, 5], // kty: EK
    [- 1, sender.enc]
  ])
  unprotectedHeader.set(4, recipientPublicKeyJwk.kid)
  unprotectedHeader.set(-1, recipientCoseKey)
  const COSE_Encrypt0 = [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
  ]
  return encodeAsync(new Tagged(16, COSE_Encrypt0), { canonical: true })
}

export const encrypt = {
  direct: encryptDirect,
  wrap: encryptWrap
}

export const decryptWrap = async (req: RequestWrapDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== 96) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  const [recipient] = recipients

  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  const kid = recipientUnprotectedHeader.get(4).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  const decodedRecipientProtectedHeader = await decodeFirst(recipientProtectedHeader)
  const recipientAlgorithm = decodedRecipientProtectedHeader.get(1)
  const epk = recipientUnprotectedHeader.get(-1)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(3, recipientAlgorithm) // EPK is allowed to have an alg
  const suite = suites[receiverPrivateKeyJwk.alg as JOSE_HPKE_ALG]
  const info = await computeInfo(decodedRecipientProtectedHeader)
  const hpkeRecipient = await suite.createRecipientContext({
    info,
    recipientKey: await privateKeyFromJwk(receiverPrivateKeyJwk),
    enc: epk.get(-1) // ek
  })
  const hpkeSealAad = computeHPKEAad(protectedHeader, recipientProtectedHeader)
  const contentEncryptionKey = await hpkeRecipient.open(recipientCipherText, hpkeSealAad)
  const iv = unprotectedHeader.get(5)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER) // good
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(1)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(contentEncryptionKey))
}

export const decryptDirect = async (req: RequestDirectDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== 16) {
    throw new Error('Only tag 16 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext] = decoded.value
  const kid = unprotectedHeader.get(4).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const recipientAlgorithm = unprotectedHeader.get(1)
  const epk = unprotectedHeader.get(-1)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(3, recipientAlgorithm) // EPK is allowed to have an alg
  const suite = suites[receiverPrivateKeyJwk.alg as JOSE_HPKE_ALG]
  const info = await computeInfo(decodedProtectedHeader)
  const hpkeRecipient = await suite.createRecipientContext({
    info,
    recipientKey: await privateKeyFromJwk(receiverPrivateKeyJwk),
    enc: epk.get(-1) // ek
  })
  const hpkeSealAad = computeHPKEAad(protectedHeader)
  const plaintext = await hpkeRecipient.open(ciphertext, hpkeSealAad)
  return plaintext
}

export const decrypt = {
  wrap: decryptWrap,
  direct: decryptDirect
}