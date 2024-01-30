

import { JWK } from 'jose'


export type JsonWebKey = JWK

export type CoseMapKey = string | number
export type CoseMapValue = Uint8Array | ArrayBuffer | string | number | Map<CoseMapKey, unknown>

export type CoseKey = Map<CoseMapKey, CoseMapValue>

export * from './cose/algorithms'
export * from './cose/header-parameters'
export * from './cose/key-common-parameters'

import * as key from './cose/key'
import * as attached from './cose/attached'
import * as detached from './cose/detached'
export * from './cose/sign1'

import * as cbor from './cbor'

export * from './spice'

export { cbor, key, attached, detached }