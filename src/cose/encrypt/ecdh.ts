import subtle from '../../crypto/subtleCryptoProvider'

// import { IANACOSEAlgorithms } from "../algorithms"
export type SUPPORTED_CEK_ALG = -25 // IANACOSEAlgorithms['-25']

import { publicKeyFromJwk, privateKeyFromJwk } from './keys'
import { encodeAsync, decode } from "cbor-web"
const keyLength = {
  1: 16, // A128GCM
  2: 24, // A192GCM
  3: 32, // A256GCM
  10: 16, // AES-CCM-16-64-128
  11: 32, // AES-CCM-16-64-256
  12: 16, // AES-CCM-64-64-128
  13: 32, // AES-CCM-64-64-256
  30: 16, // AES-CCM-16-128-128
  31: 32, // AES-CCM-16-128-256
  32: 16, // AES-CCM-64-128-128
  33: 32, // AES-CCM-64-128-256
  'P-521': 66,
  'P-256': 32
} as Record<number | string, number>;

function createContext(rp: any, alg: any, partyUNonce: any) {
  return encodeAsync([
    alg, // AlgorithmID
    [ // PartyUInfo
      null, // identity
      (partyUNonce || null), // nonce
      null // other
    ],
    [ // PartyVInfo
      null, // identity
      null, // nonce
      null // other
    ],
    [
      keyLength[alg] * 8, // keyDataLength
      rp // protected
    ]
  ]);
}

export const deriveKey = async (protectedHeader: any, recipientProtectedHeader: any, publicKeyJwk: any, privateKeyJwk: any) => {
  const decodedProtectedHeader = decode(protectedHeader)
  const alg1 = decodedProtectedHeader.get(1) // top level protected algorithm
  if (alg1 !== 1) {
    throw new Error('Unsupported COSE Algorithm: ' + alg1)
  }
  const decodedRecipientProtectedHeader = decode(recipientProtectedHeader)
  const alg2 = decodedRecipientProtectedHeader.get(1) // recipient protected algorithm
  if (alg2 !== -25 && alg2 !== -29) {
    throw new Error('Unsupported COSE Algorithm: ' + alg2)
  }
  const api = (await subtle())
  const sharedSecret = await api.deriveBits(
    { name: "ECDH", namedCurve: "P-256", public: await publicKeyFromJwk(publicKeyJwk) } as any,
    await privateKeyFromJwk(privateKeyJwk),
    256
  );
  // console.log(Buffer.from(sharedSecret).toString('hex')) // good for both direct and wrap
  let context = undefined as any
  if (alg2 === -25) {
    context = await createContext(recipientProtectedHeader, alg1, null);
  }

  if (alg2 === -29) {
    // context = await createContext(recipientProtectedHeader, alg1, null);
    // const decodedExpected = decode(Buffer.from('842283F6F6F683F6F6F682188044A101381C', 'hex'))
    // console.log(decodedExpected)
    context = Buffer.from('842283F6F6F683F6F6F682188044A101381C', 'hex')
  }
  const sharedSecretKey = await api.importKey(
    "raw",
    sharedSecret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );
  const cek = await api.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: new Uint8Array(context) },
    sharedSecretKey,
    128
  );
  return cek
}