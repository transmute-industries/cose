
import crypto from 'crypto';

import { publicKeyFromJwk, privateKeyFromJwk } from './keys';
import { createHash, createSecretKey, createDecipheriv, createCipheriv } from 'node:crypto'

// https://github.com/panva/jose/blob/08eff759a032585a950d79e6989dfcb373a8900e/src/lib/buffer_utils.ts#L49
// had to pull all this stuff out, becuase its not exposed in the module...

const digest: any = (
  algorithm: 'sha256' | 'sha384' | 'sha512',
  data: Uint8Array,
): Uint8Array => createHash(algorithm).update(data).digest()

const MAX_INT32 = 2 ** 32

function writeUInt32BE(buf: Uint8Array, value: number, offset?: number) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`)
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset)
}
export function uint32be(value: number) {
  const buf = new Uint8Array(4)
  writeUInt32BE(buf, value)
  return buf
}

export async function concatKdf(secret: Uint8Array, bits: number, value: Uint8Array) {
  const iterations = Math.ceil((bits >> 3) / 32)
  const res = new Uint8Array(iterations * 32)
  for (let iter = 0; iter < iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length)
    buf.set(uint32be(iter + 1))
    buf.set(secret, 4)
    buf.set(value, 4 + secret.length)
    res.set(await digest('sha256', buf), iter * 32)
  }
  return res.slice(0, bits >> 3)
}


export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  for (const buffer of buffers) {
    buf.set(buffer, i)
    i += buffer.length
  }
  return buf
}

export function lengthAndInput(input: Uint8Array) {
  return concat(uint32be(input.length), input)
}

export const deriveKey = async (publicKeyJwk: any, privateKeyJwk: any) => {
  const length = Math.ceil(parseInt('P-256'.substr(-3), 10) / 8) << 3
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: await publicKeyFromJwk(publicKeyJwk),
      },
      await privateKeyFromJwk(privateKeyJwk),
      length,
    ),
  )
  const algorithm = 'ECDH-ES+A128KW'
  const keyLength = 128;
  const apu = new Uint8Array(0)
  const apv = new Uint8Array(0)
  const encoder = new TextEncoder()
  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )
  return concatKdf(sharedSecret, keyLength, value);
}

export const wrap: any = (alg: string, key: unknown, cek: Uint8Array) => {
  const size = parseInt(alg.slice(1, 4), 10)
  const algorithm = `aes${size}-wrap`
  const keyObject = createSecretKey(key as any)
  const cipher = createCipheriv(algorithm, keyObject, Buffer.alloc(8, 0xa6))
  return concat(cipher.update(cek), cipher.final())
}

export const unwrap: any = (
  alg: string,
  key: Uint8Array,
  encryptedKey: Uint8Array,
) => {
  const size = parseInt(alg.slice(1, 4), 10)
  const algorithm = `aes${size}-wrap`
  const keyObject = createSecretKey(key as any)
  const cipher = createDecipheriv(algorithm, keyObject, Buffer.alloc(8, 0xa6))
  return concat(cipher.update(encryptedKey), cipher.final())
}

export function gcmEncrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
) {
  const keySize = parseInt(enc.slice(1, 4), 10)
  const algorithm = `aes-${keySize}-gcm`
 
  const cipher = createCipheriv(algorithm, cek, iv, { authTagLength: 16 } as any) as any
  if (aad.byteLength) {
    cipher.setAAD(aad, { plaintextLength: plaintext.length })
  }

  const ciphertext = cipher.update(plaintext)
  cipher.final()
  const tag = cipher.getAuthTag()

  return { ciphertext, tag }
}


export function gcmDecrypt(
  enc: string,
  cek:  Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
) {

  const keySize = parseInt(enc.slice(1, 4), 10)
  const algorithm = `aes-${keySize}-gcm`

  try {
    const decipher = createDecipheriv(algorithm, cek, iv, { authTagLength: 16 } as any) as any
    decipher.setAuthTag(tag)
    if (aad.byteLength) {
      decipher.setAAD(aad, { plaintextLength: ciphertext.length })
    }

    const plaintext = decipher.update(ciphertext)
    decipher.final()
    return plaintext
  } catch (e){
    console.log(e)
    throw new Error('XXXX Decryption failed.')
  }
}

