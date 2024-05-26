


import { ml_kem768 } from '@noble/post-quantum/ml-kem';

import { COSE_Encrypt0, Direct, KeyTypeAlgorithms, Protected, Unprotected, UnprotectedHeader } from '../../Params'
import { RequestDirectEncryption, RequestDirectDecryption } from '../types'
import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import { computeInfo } from './computeInfo'
import { suites, JOSE_HPKE_ALG } from './suites'

import { publicKeyFromJwk, privateKeyFromJwk, computeHPKEAad } from './common'
import { base64url } from 'jose'

import * as aes from '../aes'

import { CipherSuite, KemId, KdfId, AeadId } from 'hpke-js'
import { EMPTY_BUFFER, toArrayBuffer } from '../../../cbor';

import { createAAD } from '../utils';

// from hpke-js
/**
 * Converts integer to octet string. I2OSP implementation.
 */
export function i2Osp(n: number, w: number): Uint8Array {
  if (w <= 0) {
    throw new Error("i2Osp: too small size");
  }
  if (n >= 256 ** w) {
    throw new Error("i2Osp: too large integer");
  }
  const ret = new Uint8Array(w);
  for (let i = 0; i < w && n; i++) {
    ret[w - (i + 1)] = n % 256;
    n = n >> 8;
  }
  return ret;
}

const dhkemsuite = new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256,
  kdf: KdfId.HkdfSha256,
  aead: AeadId.Aes128Gcm,
});

const handleDHKemEncrypt = async (req: RequestDirectEncryption) => {
  if (req.unprotectedHeader === undefined) {
    req.unprotectedHeader = UnprotectedHeader([])
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



const Expand = async (prk: Uint8Array, info: Uint8Array, length: number) => {
  // 🔥 possibly incorrect.
  return dhkemsuite.kdf.expand(prk, info, length)
}

const Extract = async (salt: Uint8Array, ikm: Uint8Array) => {
  // 🔥 possibly incorrect.
  return dhkemsuite.kdf.extract(salt, ikm)
}

const suite_id = Buffer.concat([
  Buffer.from('HPKE'),
  Buffer.from(i2Osp(0xFFFF, 2)), // 🔥 Not a real kem id  🔥
  Buffer.from(i2Osp(0x0001, 2)), // HKDF-SHA256, 32
  Buffer.from(i2Osp(0x0001, 2))  // AES-128-GCM
])

// def LabeledExtract(salt, label, ikm):
// labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
// return Extract(salt, labeled_ikm)
const LabeledExtract = async (salt: Uint8Array, label: Uint8Array, ikm: Uint8Array) => {
  const labeled_ikm = Buffer.concat([
    new TextEncoder().encode('HPKE-v1'),
    suite_id,
    Buffer.from(''),
    ikm
  ])
  return Extract(salt, labeled_ikm)
}

// def LabeledExpand(prk, label, info, L):
//      labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
//                            label, info)
//      return Expand(prk, labeled_info, L)
const LabeledExpand = async (prk: Uint8Array, label: Uint8Array, info: Uint8Array, length: number) => {
  const labeled_info = Buffer.concat([
    Buffer.from(i2Osp(length, 2)),
    Buffer.from("HPKE-v1"),
    suite_id,
    label,
    info
  ])
  return Expand(prk, labeled_info, 32)
}

// def ExtractAndExpand(dh, kem_context):
//    eae_prk = LabeledExtract("", "eae_prk", dh)
//    shared_secret = LabeledExpand(eae_prk, "shared_secret",
//                                  kem_context, Nsecret)
//    return shared_secret
const ExtractAndExpand = async (ss: Uint8Array, ct: Uint8Array) => {
  const eae_prk = await LabeledExtract(new TextEncoder().encode(''), new TextEncoder().encode('eae_prk'), ss)
  const shared_secret = LabeledExpand(new Uint8Array(eae_prk), new TextEncoder().encode('shared_secret'), ct, 32)
  return shared_secret
}

// 🔥 This is wrong.
// need to follow https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-hpke-mlkem-00#name-encap-and-decap
const sharedSecretToContentEncryptionKey = async (ss: Uint8Array, ct: Uint8Array) => {
  return ExtractAndExpand(ss, ct)
}

const handleMLKemEncrypt = async (req: RequestDirectEncryption) => {
  const protectedHeader = await encodeAsync(req.protectedHeader)
  const unprotectedHeader = req.unprotectedHeader || new Map<any, any>();
  const [recipientPublicKeyJwk] = req.recipients.keys
  const publicKey = base64url.decode(recipientPublicKeyJwk.x)
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const kemCt = cipherText;
  const aeadContentEncryptionKey = await sharedSecretToContentEncryptionKey(sharedSecret, cipherText)
  const aeadAlg = 1; // AES 128 GCM
  const iv = await aes.getIv(aeadAlg) // random for each direct encryption
  const externalAad = EMPTY_BUFFER
  // const hpkeSealAad = computeHPKEAad(protectedHeader) // confused why I don't need this...
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  const ct = await aes.encrypt(aeadAlg, new Uint8Array(req.plaintext), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(aeadContentEncryptionKey))
  // HPKE direct mode prefix iv?
  const ctWithIv = Buffer.concat([
    Buffer.from(iv),
    Buffer.from(ct)
  ])
  if (recipientPublicKeyJwk.kid) {
    unprotectedHeader.set(Unprotected.Kid, recipientPublicKeyJwk.kid)
  }
  unprotectedHeader.set(Unprotected.Ek, toArrayBuffer(kemCt))
  return encodeAsync(new Tagged(COSE_Encrypt0, [
    protectedHeader,
    unprotectedHeader,
    ctWithIv,
  ]), { canonical: true })
}

export const encryptDirect = async (req: RequestDirectEncryption) => {
  const alg = req.protectedHeader.get(Protected.Alg)
  if (alg === Direct['HPKE-Base-P256-SHA256-AES128GCM']) {
    return handleDHKemEncrypt(req)
  }
  if (alg === Direct['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']) {
    return handleMLKemEncrypt(req)
  }
  throw new Error('Unsupported HPKE algorithm')
}


const handleDHKemDecrypt = async (req: RequestDirectDecryption) => {
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


const handleMLKemDecrypt = async (req: RequestDirectDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== COSE_Encrypt0) {
    throw new Error('Only tag 16 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ctWithIv] = decoded.value
  const kid = unprotectedHeader.get(Unprotected.Kid).toString();
  const receiverPrivateKeyJwk = req.recipients.keys.find((k) => {
    return k.kid === kid
  })
  const ek = unprotectedHeader.get(Unprotected.Ek) // kem-ct
  const iv = ctWithIv.slice(0, 16) // AES-128-GCM iv length
  const encryptedContent = ctWithIv.slice(16, ctWithIv.length)
  const secretKey = base64url.decode(receiverPrivateKeyJwk.d)
  const sharedSecret = ml_kem768.decapsulate(ek, secretKey);
  const aeadContentEncryptionKey = await sharedSecretToContentEncryptionKey(sharedSecret, ek)
  const aeadAlg = 1; // AES 128 GCM
  const externalAad = EMPTY_BUFFER
  // const hpkeSealAad = computeHPKEAad(protectedHeader) // confused why I don't need this...
  const aad = await createAAD(protectedHeader, 'Encrypt', externalAad)
  return aes.decrypt(aeadAlg, encryptedContent, new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(aeadContentEncryptionKey))
}


export const decryptDirect = async (req: RequestDirectDecryption) => {
  const decoded = await decodeFirst(req.ciphertext)
  if (decoded.tag !== COSE_Encrypt0) {
    throw new Error('Only tag 16 cose encrypt are supported')
  }
  const [protectedHeader] = decoded.value
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  const alg = decodedProtectedHeader.get(Protected.Alg)
  if (alg === Direct['HPKE-Base-P256-SHA256-AES128GCM']) {
    return handleDHKemDecrypt(req)
  }
  if (alg === Direct['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']) {
    return handleMLKemDecrypt(req)
  }
  throw new Error('Unsupported HPKE algorithm')
}
