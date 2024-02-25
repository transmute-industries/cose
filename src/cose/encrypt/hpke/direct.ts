

import { COSE_Encrypt0, Direct, Protected, Unprotected, UnprotectedHeader } from '../../Params'
import { RequestDirectEncryption, RequestDirectDecryption } from '../types'
import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import { computeInfo } from './computeInfo'
import { suites, JOSE_HPKE_ALG } from './suites'

import { publicKeyFromJwk, privateKeyFromJwk, computeHPKEAad } from './common'

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
