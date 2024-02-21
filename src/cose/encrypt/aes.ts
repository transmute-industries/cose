import subtle from '../../crypto/subtleCryptoProvider'

export type COSE_AES_ALG = 1 // AES GCM

const coseAlgToTagLength = {
  1: 128,
} as Record<COSE_AES_ALG, number>;

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



// async function encryptGCM(string,key) {
//   let encoded = new TextEncoder().encode(string);
//   let iv = crypto.getRandomValues(new Uint8Array(12));
//   let encrypted = await crypto.subtle.encrypt({"name":"AES-GCM","iv":iv}, key, encoded);
//   return encrypted = {"encrypted":encrypted, "iv": iv};
// 
