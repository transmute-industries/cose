import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

import { generate } from "../key"
import { JsonWebKey } from "../key"

import { Tagged, decodeFirst, encodeAsync } from "cbor-web"

import subtle from '../../crypto/subtleCryptoProvider'

export const COSE_Encrypt_Tag = 96

import { EMPTY_BUFFER } from "../../cbor"
import { base64url } from "jose"


const HKDF = require('node-hkdf-sync');

export async function encryptMessage(message: Uint8Array, key: CryptoKey, iv: Uint8Array, aad: ArrayBuffer) {
  const api = (await subtle())
  return api.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: aad },
    key,
    message,
  );
}

export async function decryptMessage(message: Uint8Array, key: CryptoKey, iv: Uint8Array, aad: ArrayBuffer) {
  const api = (await subtle())
  return api.decrypt(
    { name: "AES-GCM", iv: iv, additionalData: aad },
    key,
    message,
  );
}


// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// eslint-disable-next-line @typescript-eslint/no-empty-function
const nodeCrypto = import('crypto').catch(() => { }) as any

export const getRandomBytes = async (byteLength = 16) => {
  try {
    return crypto.getRandomValues(new Uint8Array(byteLength))
  } catch {
    return (await nodeCrypto).randomFillSync(new Uint8Array(byteLength))
  }
}

export type JWKS = {
  keys: JsonWebKey[]
}

export type RequestEncryption = {
  protectedHeader: Map<any, any>
  unprotectedHeader: Map<any, any>
  plaintext: Uint8Array,
  recipients: JWKS
}

export const publicKeyFromJwk = async (publicKeyJwk: any) => {
  const api = (await subtle())
  const publicKey = await api.importKey(
    'jwk',
    publicKeyJwk,
    {
      name: 'ECDH',
      namedCurve: publicKeyJwk.crv,
    },
    true,
    [],
  )
  return publicKey;
}

export const privateKeyFromJwk = async (privateKeyJwk: any) => {
  const api = (await subtle())
  const privateKey = await api.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: privateKeyJwk.crv,
    },
    true,
    ['deriveBits', 'deriveKey'],
  )
  return privateKey
}

// probably not correct.... going to start by implementing decrypt
export const encrypt = async (req: RequestEncryption) => {
  if (req.recipients.keys.length !== 1) {
    throw new Error('Direct encryption requires a single recipient')
  }
  const recipientJWK = req.recipients.keys[0]
  if (recipientJWK.crv !== 'P-256') {
    throw new Error('Only P-256 is supported currently')
  }
  const privateEpk: any = await generate('ES256', "application/jwk+json")
  delete privateEpk.alg
  const api = (await subtle())
  const contentEncryptionKey = await api.deriveKey({
    name: "ECDH",
    public: await publicKeyFromJwk(recipientJWK),
  },
    await privateKeyFromJwk(privateEpk),
    {
      name: "AES-GCM",
      length: 128,
    },
    true,
    ["encrypt", "decrypt"],
  )
  const cek = Buffer.from(await api.exportKey('raw', contentEncryptionKey))
  const symmetricKey = await api.importKey('raw', cek, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ])

  const iv = await getRandomBytes(12);


  const message = req.plaintext
  const protectedHeader = await encodeAsync(req.protectedHeader)


  const ct = await encryptMessage(message, symmetricKey, iv, protectedHeader)

  const recipientProtectedHeader = await encodeAsync(new Map<number, any>([
    [1, -25],// alg : ECDH-ES + HKDF-256
  ]))
  const recipientUnprotectedHeader = new Map<number, any>([
    [4, recipientJWK.kid], //kid
    [-1, new Map<number, any>([ // epk
      [1, 2], // kty : EC2
      [-1, 1], // crv P-256
      [-2, Buffer.from(privateEpk.x, 'base64')], // x
      [-3, Buffer.from(privateEpk.y, 'base64')] // x
    ])]
  ])

  const recipients = [[recipientProtectedHeader, recipientUnprotectedHeader, EMPTY_BUFFER]]

  const COSE_Encrypt = [
    protectedHeader,
    req.unprotectedHeader,
    ct,
    recipients
  ] as any

  return encodeAsync(new Tagged(COSE_Encrypt_Tag, COSE_Encrypt), { canonical: true })
}

export type RequestDecryption = {
  ciphertext: BufferSource,
  recipients: JWKS
}


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

async function createAAD(protectedHeader: BufferSource, context: any, externalAAD: BufferSource) {
  const encStructure = [
    context,
    protectedHeader,
    externalAAD
  ];
  return encodeAsync(encStructure);
}

export const decrypt = async (req: RequestDecryption) => {
  const decoded = await decodeFirst(req.ciphertext as any)
  if (decoded.tag !== 96) {
    throw new Error('Only tag 96 cose encrypt are supported')
  }
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = decoded.value
  const decodedProtectedHeader = await decodeFirst(protectedHeader)
  if (recipients.length !== 1) {
    throw new Error('Expected a single recipient for direct decryption')
  }
  const [recipient] = recipients
  const [recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText] = recipient
  if (recipientCipherText.length !== 0) {
    throw new Error('Expected recipient cipher text length to the be zero')
  }
  const epk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64url.encode(recipientUnprotectedHeader.get(-1).get(-2)),
    y: base64url.encode(recipientUnprotectedHeader.get(-1).get(-3))
  }
  const api = (await subtle())
  const receiverPrivateKey = req.recipients.keys[0]
  const contentEncryptionKey = await api.deriveKey({
    name: "ECDH",
    public: await publicKeyFromJwk(epk),
  },
    await privateKeyFromJwk(receiverPrivateKey),
    {
      name: "AES-GCM",
      length: 128,
    },
    true,
    ["encrypt", "decrypt"],
  )

  const cek = Buffer.from(await api.exportKey('raw', contentEncryptionKey))
  console.log('cek: ', cek.toString('hex'))
  const partyUNonce = null
  const alg = decodedProtectedHeader.get(1) // top level protected algorithm
  const rp = recipientProtectedHeader;
  const context = await createContext(rp, alg, partyUNonce);
  console.log('context: ', context.toString('hex'))
  const aad = await createAAD(protectedHeader, 'Encrypt', EMPTY_BUFFER)
  console.log('aad: ', (await aad).toString('hex'))

  const symmetricKey = await api.importKey('raw', cek, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ])

  const iv = unprotectedHeader.get(5)
  console.log('iv: ', iv.toString('hex'))

  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  // const recipientPublicKey = Buffer.concat([
  //   Buffer.from('04', 'hex'),
  //   Buffer.from(receiverPrivateKey.x as any, 'base64'),
  //   Buffer.from(receiverPrivateKey.y as any, 'base64'),
  // ]);

  // const hkdf = await suite.kdf.extract(context, cek)

  // console.log(Buffer.from(hkdf).toString('hex'))

  const hkdf = new HKDF('sha256', undefined, cek);
  const key = hkdf.derive(context, 16); // A128GCM
  console.log(key.toString('hex'))

  // const symmetricKey = await api.importKey('raw', cek, "AES-GCM", true, [
  //   "encrypt",
  //   "decrypt",
  // ])
  // TODO: make this work end to end in node, then replace node functions with webcrypto.

  const pt = await decryptMessage(ciphertext, symmetricKey, iv, aad)
  console.log(pt)

}