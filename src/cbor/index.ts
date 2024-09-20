export * from './diag'

import { encodeCanonical, encode, decode, encodeAsync, decodeFirst, decodeFirstSync, diagnose, Tagged } from 'cbor-web'

import { toArrayBuffer } from './toArrayBuffer'

export const Sign1Tag = 18;

export const EMPTY_BUFFER = toArrayBuffer(new Uint8Array())

export { toArrayBuffer }

export { encodeCanonical, encode, decode, encodeAsync, decodeFirst, decodeFirstSync, diagnose, Tagged }


