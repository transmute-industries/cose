

import { JWK } from 'jose'


export type JsonWebKey = JWK

export type CoseMapKey = string | number
export type CoseMapValue = ArrayBuffer | string | number | Map<CoseMapKey, unknown>

export type CoseKey = Map<CoseMapKey, CoseMapValue>

export * from './lib'

export * from './cose/algorithms'
export * from './cose/header-parameters'
export * from './cose/key-common-parameters'

import * as key from './cose/key'

export { key }