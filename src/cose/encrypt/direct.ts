
import { convertCoseKeyToJsonWebKey, convertJsonWebKeyToCoseKey, generate, publicFromPrivate } from "../key"

import { Tagged, decode, decodeFirst, encodeAsync } from "cbor-web"

import { EMPTY_BUFFER } from "../../cbor"

import * as aes from './aes'
import * as ecdh from './ecdh'

import { COSE_Encrypt, Direct, Epk, KeyAgreement, Protected, ProtectedHeader, Unprotected } from "../Params"

import { createAAD } from './utils'

import { RequestDirectEncryption, RequestDirectDecryption } from './types'

import * as hpke from './hpke'
import { UnprotectedHeader } from "../Params"

import { toArrayBuffer } from "../../cbor"

const getCoseAlgFromRecipientJwk = (jwk: any) => {
  if (jwk.crv === 'P-256') {
    return KeyAgreement["ECDH-ES+HKDF-256"]
  }
}

export const encrypt = async (req: RequestDirectEncryption) => {
  if (req.unprotectedHeader === undefined) {
    req.unprotectedHeader = UnprotectedHeader([])
  }
  if (req.recipients.keys.length !== 1) {
    throw new Error('Direct encryption requires a single recipient')
  }
  const recipientPublicKeyJwk = req.recipients.keys[0]
  if (recipientPublicKeyJwk.crv !== 'P-256' && recipientPublicKeyJwk.kty !== 'ML-KEM') {
    throw new Error('Only P-256 DHKEM and ML-KEM-768 are currently supported')
  }
  if (Object.keys(Direct).includes(recipientPublicKeyJwk.alg)) {
    return hpke.encrypt.direct(req)
  }
  const alg = req.protectedHeader.get(Protected.Alg)
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader;
  const directAgreementAlgorithm = getCoseAlgFromRecipientJwk(recipientPublicKeyJwk)
  const recipientProtectedHeader = await encodeAsync(ProtectedHeader([
    [1, directAgreementAlgorithm],
  ]))
  const senderPrivateKeyJwk = await generate<any>('ES256', "application/jwk+json")
  const cek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, recipientPublicKeyJwk, senderPrivateKeyJwk)
  const iv = await aes.getIv(alg);
  unprotectedHeader.set(Unprotected.Iv, iv)
  const senderPublicKeyJwk = publicFromPrivate<any>(senderPrivateKeyJwk)
  const senderPublicCoseKey = await convertJsonWebKeyToCoseKey(senderPublicKeyJwk)
  const unprotectedParams = [[Unprotected.Epk, senderPublicCoseKey]] as any[]
  if (recipientPublicKeyJwk.kid) {
    unprotectedParams.push([Unprotected.Kid, recipientPublicKeyJwk.kid],)
  }
  const recipientUnprotectedHeader = UnprotectedHeader(unprotectedParams)
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  const ciphertext = await aes.encrypt(alg, new Uint8Array(req.plaintext), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
  const recipients = [[recipientProtectedHeader, recipientUnprotectedHeader, EMPTY_BUFFER]]
  return encodeAsync(new Tagged(COSE_Encrypt, [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
    recipients
  ]), { canonical: true })
}

export const decrypt = async (req: RequestDirectDecryption) => {
  const receiverPrivateKeyJwk = req.recipients.keys[0]
  if (Object.keys(Direct).includes(receiverPrivateKeyJwk.alg)) {
    return hpke.decrypt.direct(req)
  }
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== COSE_Encrypt) {
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
  const recipientAlgorithm = decodedRecipientProtectedHeader.get(Protected.Alg)
  const epk = recipientUnprotectedHeader.get(Unprotected.Epk)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(Epk.Alg, recipientAlgorithm)
  const senderPublicKeyJwk = await convertCoseKeyToJsonWebKey(epk)
  const cek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  const iv = unprotectedHeader.get(Unprotected.Iv)
  const decodedProtectedHeader = decode(protectedHeader)
  const alg = decodedProtectedHeader.get(Protected.Alg)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}