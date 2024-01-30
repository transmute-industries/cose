import * as cbor from 'cbor-web'
import { toArrayBuffer } from '../../cbor'

export const Sign1Tag = 18;

export const EMPTY_BUFFER = toArrayBuffer(new Uint8Array())

export const Tagged = cbor.Tagged;
