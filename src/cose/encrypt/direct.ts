
import { convertCoseKeyToJsonWebKey, convertJsonWebKeyToCoseKey, generate, publicFromPrivate } from "../key"
import { JsonWebKey } from "../key"
import { Tagged, decode, decodeFirst, encodeAsync } from "cbor-web"
export const COSE_Encrypt_Tag = 96

import { EMPTY_BUFFER } from "../../cbor"

import * as aes from './aes'
import * as ecdh from './ecdh'

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// eslint-disable-next-line @typescript-eslint/no-empty-function
const nodeCrypto = import('crypto').catch(() => { }) as any

export const getRandomBytes = async (byteLength = 16) => {
  try {
    return crypto.getRandomValues(new Uint8Array(byteLength))
  } catch {
    return (await nodeCrypto).randomFillSync(new Uint8Array(byteLength))
  }
}

export type JWKS = {
  keys: JsonWebKey[]
}

export type RequestEncryption = {
  protectedHeader: Map<any, any>
  unprotectedHeader: Map<any, any>
  plaintext: Uint8Array,
  recipients: JWKS
}

const getIv = async (alg: number) => {
  let ivLength = 16
  if (alg === 1) {
    ivLength = 16
  }
  return getRandomBytes(ivLength);
}

const getCoseAlgFromRecipientJwk = (jwk: any) => {
  if (jwk.crv === 'P-256') {
    return -25 // alg : ECDH-ES + HKDF-256
  }
}

export const encrypt = async (req: RequestEncryption) => {
  if (req.recipients.keys.length !== 1) {
    throw new Error('Direct encryption requires a single recipient')
  }
  const recipientPublicKeyJwk = req.recipients.keys[0]
  if (recipientPublicKeyJwk.crv !== 'P-256') {
    throw new Error('Only P-256 is supported currently')
  }
  const alg = req.protectedHeader.get(1)
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader;
  const directAgreementAlgorithm = getCoseAlgFromRecipientJwk(recipientPublicKeyJwk)
  const recipientProtectedHeader = await encodeAsync(new Map<number, any>([
    [1, directAgreementAlgorithm],
  ]))
  const senderPrivateKeyJwk = await generate<any>('ES256', "application/jwk+json")
  const cek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, recipientPublicKeyJwk, senderPrivateKeyJwk)
  const iv = await getIv(alg);
  unprotectedHeader.set(5, iv)
  const senderPublicKeyJwk = publicFromPrivate<any>(senderPrivateKeyJwk)
  const senderPublicCoseKey = await convertJsonWebKeyToCoseKey(senderPublicKeyJwk)
  const unprotectedParams = [[-1, senderPublicCoseKey]] as any[]
  if (recipientPublicKeyJwk.kid) {
    unprotectedParams.push([4, recipientPublicKeyJwk.kid],)
  }
  const recipientUnprotectedHeader = new Map<number, any>(unprotectedParams)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER)
  const ciphertext = await aes.encrypt(alg, new Uint8Array(req.plaintext), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
  const recipients = [[recipientProtectedHeader, recipientUnprotectedHeader, EMPTY_BUFFER]]
  const COSE_Encrypt = [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
    recipients
  ]
  return encodeAsync(new Tagged(COSE_Encrypt_Tag, COSE_Encrypt), { canonical: true })
}

export type RequestDecryption = {
  ciphertext: any,
  recipients: JWKS
}

async function createAAD(protectedHeader: BufferSource, context: any, externalAAD: BufferSource) {
  const encStructure = [
    context,
    protectedHeader,
    externalAAD
  ];
  return encodeAsync(encStructure);
}

export const decrypt = async (req: RequestDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== 96) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  if (recipients.length !== 1) {
    throw new Error('Expected a single recipient for direct decryption')
  }
  const [recipient] = recipients
  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  if (recipientCipherText.length !== 0) {
    throw new Error('Expected recipient cipher text length to the be zero')
  }
  const decodedRecipientProtectedHeader = decode(recipientProtectedHeader)
  const recipientAlgorithm = decodedRecipientProtectedHeader.get(1)
  const epk = recipientUnprotectedHeader.get(-1)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(3, recipientAlgorithm)
  const senderPublicKeyJwk = await convertCoseKeyToJsonWebKey(epk)
  const receiverPrivateKeyJwk = req.recipients.keys[0]
  const cek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER)
  const iv = unprotectedHeader.get(5)
  const decodedProtectedHeader = decode(protectedHeader)
  const alg = decodedProtectedHeader.get(1)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}