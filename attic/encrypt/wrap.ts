
import { convertCoseKeyToJsonWebKey, convertJsonWebKeyToCoseKey, generate, publicFromPrivate } from "../key"

import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import * as aes from './aes'
import * as ecdh from './ecdh'
import { createAAD, } from './utils'

import { RequestWrapDecryption, RequestWrapEncryption } from './types'

import { EMPTY_BUFFER } from "../../cbor"

import * as hpke from './hpke'
import { UnprotectedHeader, COSE_Encrypt, Unprotected, KeyWrap, KeyAgreementWithKeyWrap, Aead, ProtectedHeader, Protected, Epk } from "../Params"

import { toArrayBuffer } from "../../cbor"

export const decrypt = async (req: RequestWrapDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  const [recipient] = recipients
  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  const kid = recipientUnprotectedHeader.get(Unprotected.Kid).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  if (receiverPrivateKeyJwk.alg === 'HPKE-Base-P256-SHA256-AES128GCM') {
    return hpke.decrypt.wrap(req)
  }
  if (decoded.tag !== COSE_Encrypt) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const decodedRecipientProtectedHeader = await decodeFirst(recipientProtectedHeader)
  const recipientAlgorithm = decodedRecipientProtectedHeader.get(cose.header.alg)
  const epk = recipientUnprotectedHeader.get(Unprotected.Epk)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(Epk.Alg, recipientAlgorithm)
  const senderPublicKeyJwk = await convertCoseKeyToJsonWebKey(epk)
  const kek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const iv = unprotectedHeader.get(Unprotected.Iv)
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  let kwAlg = KeyWrap.A128KW
  if (recipientAlgorithm === KeyAgreementWithKeyWrap["ECDH-ES+A128KW"]) {
    kwAlg = KeyWrap.A128KW
  }
  const cek = await aes.unwrap(kwAlg, recipientCipherText, new Uint8Array(kek))
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(cose.header.alg)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}



const getCoseAlgFromRecipientJwk = (jwk: any) => {
  if (jwk.crv === 'P-256') {
    return KeyAgreementWithKeyWrap["ECDH-ES+A128KW"]
  }
}


export const encrypt = async (req: RequestWrapEncryption) => {
  if (req.unprotectedHeader === undefined) {
    req.unprotectedHeader = UnprotectedHeader([])
  }
  if (req.recipients.keys.length !== 1) {
    throw new Error('Direct encryption requires a single recipient')
  }
  const recipientPublicKeyJwk = req.recipients.keys[0]
  if (recipientPublicKeyJwk.crv !== 'P-256') {
    throw new Error('Only P-256 is supported currently')
  }

  if (recipientPublicKeyJwk.alg === 'HPKE-Base-P256-SHA256-AES128GCM') {
    return hpke.encrypt.wrap(req)
  }
  const alg = req.protectedHeader.get(cose.header.alg)
  if (alg !== Aead.A128GCM) {
    throw new Error('Only A128GCM is supported currently')
  }
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader;
  const keyAgreementWithKeyWrappingAlgorithm = getCoseAlgFromRecipientJwk(recipientPublicKeyJwk)
  const recipientProtectedHeader = await encodeAsync(ProtectedHeader([
    [cose.header.alg, KeyAgreementWithKeyWrap["ECDH-ES+A128KW"]],
  ]))
  const senderPrivateKeyJwk = await generate<any>('ES256', "application/jwk+json")
  const kek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, recipientPublicKeyJwk, senderPrivateKeyJwk)

  const cek = await aes.generateKey(alg);
  const iv = await aes.getIv(alg);
  unprotectedHeader.set(Unprotected.Iv, iv)
  let kwAlg = KeyWrap.A128KW
  if (keyAgreementWithKeyWrappingAlgorithm === KeyAgreementWithKeyWrap["ECDH-ES+A128KW"]) {
    kwAlg = KeyWrap.A128KW
  }
  const encryptedKey = await aes.wrap(kwAlg, cek, new Uint8Array(kek))
  const senderPublicKeyJwk = publicFromPrivate<any>(senderPrivateKeyJwk)
  const senderPublicCoseKey = await convertJsonWebKeyToCoseKey(senderPublicKeyJwk)
  const unprotectedParams = [[Unprotected.Epk, senderPublicCoseKey]] as any[]
  if (recipientPublicKeyJwk.kid) {
    unprotectedParams.push([Unprotected.Kid, recipientPublicKeyJwk.kid],)
  }
  const recipientUnprotectedHeader = UnprotectedHeader(unprotectedParams)
  const externalAad = req.aad ? toArrayBuffer(req.aad) : EMPTY_BUFFER
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  const ciphertext = await aes.encrypt(
    alg,
    new Uint8Array(req.plaintext),
    new Uint8Array(iv),
    new Uint8Array(aad),
    new Uint8Array(cek)
  )
  const recipients = [[recipientProtectedHeader, recipientUnprotectedHeader, encryptedKey]]

  return encodeAsync(new Tagged(COSE_Encrypt, [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
    recipients
  ]), { canonical: true })
}