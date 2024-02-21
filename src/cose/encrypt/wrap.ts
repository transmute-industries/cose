
import { decodeFirst } from "cbor-web"

import { convertCoseKeyToJsonWebKey } from "../key"

import * as aes from './aes'
import * as ecdh from './ecdh'
import { createAAD, getRandomBytes } from './utils'

import { EMPTY_BUFFER } from "../../cbor"

import * as mixed from './mixed'

export type RequestWrapDecryption = {
  ciphertext: any,
  recipients: {
    keys: any[]
  }
}

export const decrypt = async (req: RequestWrapDecryption) => {
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
  epk.set(3, recipientAlgorithm)
  const senderPublicKeyJwk = await convertCoseKeyToJsonWebKey(epk)

  const kek = await ecdh.deriveKey(protectedHeader, recipientProtectedHeader, senderPublicKeyJwk, receiverPrivateKeyJwk)
  const iv = unprotectedHeader.get(5)
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER) // good
  let kwAlg = -3
  if (recipientAlgorithm === -29) { // ECDH-ES-A128KW
    kwAlg = -3
  }
  const cek = await aes.unwrap(kwAlg, recipientCipherText, new Uint8Array(kek))
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(1)
  return aes.decrypt(alg, ciphertext, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(cek))
}

export type RequestWrapEncryption = {
  protectedHeader: Map<any, any>
  unprotectedHeader: Map<any, any>
  plaintext: Uint8Array,
  recipients: {
    keys: any[]
  }
}

export const encrypt = async (req: RequestWrapEncryption) => {
  //
}