import * as cbor from 'cbor-web'
import { typedArrayToBuffer } from '../utils'

export const Sign1Tag = 18;

export const EMPTY_BUFFER = typedArrayToBuffer(new Uint8Array())

export const Tagged = cbor.Tagged;
