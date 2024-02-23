
import { convertCoseKeyToJsonWebKey, convertJsonWebKeyToCoseKey, generate, publicFromPrivate } from "../key"

import { Tagged, decode, decodeFirst, encodeAsync } from "cbor-web"

import { EMPTY_BUFFER } from "../../cbor"

import * as aes from './aes'
import * as ecdh from './ecdh'


import { createAAD, COSE_Encrypt_Tag, RequestDirectEncryption, RequestDirectDecryption } from './utils'


import * as hpke from './hpke'

const getCoseAlgFromRecipientJwk = (jwk: any) => {
  if (jwk.crv === 'P-256') {
    return -25 // alg : ECDH-ES + HKDF-256
  }
}

export const encrypt = async (req: RequestDirectEncryption) => {
  if (req.recipients.keys.length !== 1) {
    throw new Error('Direct encryption requires a single recipient')
  }
  const recipientPublicKeyJwk = req.recipients.keys[0]
  if (recipientPublicKeyJwk.crv !== 'P-256') {
    throw new Error('Only P-256 is supported currently')
  }
  if (recipientPublicKeyJwk.alg === hpke.primaryAlgorithm.label) {
    return hpke.encrypt.direct(req)
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
  const iv = await aes.getIv(alg);
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



export const decrypt = async (req: RequestDirectDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== 96) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const receiverPrivateKeyJwk = req.recipients.keys[0]
  if (receiverPrivateKeyJwk.alg === hpke.primaryAlgorithm.label) {
    return hpke.decrypt.direct(req)
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

  const cek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER)
  const iv = unprotectedHeader.get(5)
  const decodedProtectedHeader = decode(protectedHeader)
  const alg = decodedProtectedHeader.get(1)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}