


import { PublicKeyJwk, SecretKeyJwk } from '../sign1'

export type JsonWebKey = SecretKeyJwk | PublicKeyJwk

export type CoseMapKey = string | number
export type CoseMapValue = Uint8Array | ArrayBuffer | string | number | Map<CoseMapKey, unknown>

export type CoseKey = Map<CoseMapKey, CoseMapValue>

import { thumbprint } from './thumbprint'
export { thumbprint }
export * from './generate'
export * from './convertJsonWebKeyToCoseKey'
export * from './convertCoseKeyToJsonWebKey'
export * from './publicFromPrivate'
export * from './serialize'