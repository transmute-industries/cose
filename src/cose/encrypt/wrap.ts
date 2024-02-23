
import { convertCoseKeyToJsonWebKey, convertJsonWebKeyToCoseKey, generate, publicFromPrivate } from "../key"

import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import * as aes from './aes'
import * as ecdh from './ecdh'
import { createAAD, COSE_Encrypt_Tag, RequestWrapDecryption, RequestWrapEncryption } from './utils'

import { EMPTY_BUFFER } from "../../cbor"

import * as hpke from './hpke'

export const decrypt = async (req: RequestWrapDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  const [recipient] = recipients
  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  const kid = recipientUnprotectedHeader.get(4).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  if (receiverPrivateKeyJwk.alg === 'HPKE-Base-P256-SHA256-AES128GCM') {
    return hpke.decrypt.wrap(req)
  }
  if (decoded.tag !== 96) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const decodedRecipientProtectedHeader = await decodeFirst(recipientProtectedHeader)
  const recipientAlgorithm = decodedRecipientProtectedHeader.get(1)
  const epk = recipientUnprotectedHeader.get(-1)
  // ensure the epk has the algorithm that is set in the protected header
  epk.set(3, recipientAlgorithm)
  const senderPublicKeyJwk = await convertCoseKeyToJsonWebKey(epk)

  const kek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const iv = unprotectedHeader.get(5)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER) // good
  let kwAlg = -3
  if (recipientAlgorithm === -29) { // ECDH-ES-A128KW
    kwAlg = -3 // A128KW
  }
  const cek = await aes.unwrap(kwAlg, recipientCipherText, new Uint8Array(kek))
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(1)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}



const getCoseAlgFromRecipientJwk = (jwk: any) => {
  if (jwk.crv === 'P-256') {
    return -29 // ECDH-ES-A128KW
  }
}


export const encrypt = async (req: RequestWrapEncryption) => {
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

  const alg = req.protectedHeader.get(1)
  if (alg !== 1) {
    throw new Error('Only A128GCM is supported currently')
  }
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader;
  const keyAgreementWithKeyWrappingAlgorithm = getCoseAlgFromRecipientJwk(recipientPublicKeyJwk)
  const recipientProtectedHeader = await encodeAsync(new Map<number, any>([
    [1, keyAgreementWithKeyWrappingAlgorithm],
  ]))
  const senderPrivateKeyJwk = await generate<any>('ES256', "application/jwk+json")
  const kek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, recipientPublicKeyJwk, senderPrivateKeyJwk)
  const cek = await aes.generateKey(alg);
  const iv = await aes.getIv(alg);
  unprotectedHeader.set(5, iv)
  let kwAlg = -3
  if (keyAgreementWithKeyWrappingAlgorithm === -29) { // ECDH-ES-A128KW
    kwAlg = -3 // A128KW
  }
  const encryptedKey = await aes.wrap(kwAlg, cek, new Uint8Array(kek))
  const senderPublicKeyJwk = publicFromPrivate<any>(senderPrivateKeyJwk)
  const senderPublicCoseKey = await convertJsonWebKeyToCoseKey(senderPublicKeyJwk)
  const unprotectedParams = [[-1, senderPublicCoseKey]] as any[]
  if (recipientPublicKeyJwk.kid) {
    unprotectedParams.push([4, recipientPublicKeyJwk.kid],)
  }
  const recipientUnprotectedHeader = new Map<number, any>(unprotectedParams)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER)
  const ciphertext = await aes.encrypt(alg, new Uint8Array(req.plaintext), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
  const recipients = [[recipientProtectedHeader, recipientUnprotectedHeader, encryptedKey]]
  const COSE_Encrypt = [
    protectedHeader,
    unprotectedHeader,
    ciphertext,
    recipients
  ]
  return encodeAsync(new Tagged(COSE_Encrypt_Tag, COSE_Encrypt), { canonical: true })
}