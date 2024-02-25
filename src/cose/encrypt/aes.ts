import subtle from '../../crypto/subtleCryptoProvider'

export type COSE_AES_ALG = 1 // AES GCM

import { getRandomBytes } from './utils'

const coseAlgToTagLength = {
  1: 128,
} as Record<COSE_AES_ALG, number>;

export const getIv = async (alg: number) => {
  let ivLength = 16
  if (alg === 1) {
    ivLength = 16
  }
  return getRandomBytes(ivLength);
}

export const generateKey = async (alg: number) => {
  let keyLength = 16
  if (alg === 1) {
    keyLength = 16
  }
  return getRandomBytes(keyLength);
}

export async function decrypt(alg: COSE_AES_ALG, ct: Uint8Array, iv: Uint8Array, aad: Uint8Array, key: Uint8Array) {
  if (alg !== 1) {
    throw new Error('Unsupported cose algorithm: ' + alg)
  }
  const api = (await subtle())
  return api.decrypt({
    "name": "AES-GCM",
    "iv": iv,
    additionalData: aad,
    tagLength: coseAlgToTagLength[alg]
  },
    await api.importKey('raw', key, {
      "name": "AES-GCM"
    }, false, ['encrypt', 'decrypt']),
    ct);
}

export async function encrypt(alg: COSE_AES_ALG, pt: Uint8Array, iv: Uint8Array, aad: Uint8Array, key: Uint8Array) {
  if (alg !== 1) {
    throw new Error('Unsupported cose algorithm: ' + alg)
  }
  const api = (await subtle())
  return api.encrypt({
    "name": "AES-GCM",
    "iv": iv,
    additionalData: aad,
    tagLength: coseAlgToTagLength[alg]
  },
    await api.importKey('raw', key, {
      "name": "AES-GCM"
    }, false, ['encrypt', 'decrypt']),
    pt);
}



export async function unwrap(alg: number, encryptedKey: Uint8Array, keyEncryptionKey: Uint8Array) {
  if (alg !== -3) {
    throw new Error('Unsupported cose algorithm: ' + alg)
  }
  const api = (await subtle())
  const contentEncryptionKey = await api.unwrapKey(
    "raw",
    encryptedKey,
    await api.importKey('raw', keyEncryptionKey, {
      "name": "AES-KW"
    }, false, ['unwrapKey']),
    "AES-KW",
    { name: "AES-GCM" },
    true,
    ["decrypt"]
  );
  return api.exportKey('raw', contentEncryptionKey)

}



export async function wrap(alg: number, contentEncryptionKey: Uint8Array, keyEncryptionKey: Uint8Array) {
  if (alg !== -3) {
    throw new Error('Unsupported cose algorithm: ' + alg)
  }
  const api = (await subtle())
  return api.wrapKey(
    "raw",
    await api.importKey('raw', contentEncryptionKey, {
      "name": "AES-GCM"
    }, true, ['encrypt']),
    await api.importKey('raw', keyEncryptionKey, {
      "name": "AES-KW"
    }, true, ['wrapKey']),
    "AES-KW"
  );
}
