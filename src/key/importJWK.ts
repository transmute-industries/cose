import { CoseKeyMap } from "./types";
import * as jose from 'jose'
import { typedArrayToBuffer } from '../utils'
import keyUtils from './keyUtils'

const jwkToCoseKey = (jwk: Record<string, unknown>): CoseKeyMap => {
  const coseKey = new Map();
  for (const [key, value] of Object.entries(jwk)) {
    const coseKeyParam = keyUtils.parameters.toCOSE.get(key)
    switch (key) {
      case 'kty': {
        const coseKeyValue = keyUtils.types.toCOSE.get(value)
        coseKey.set(coseKeyParam, coseKeyValue)
        break
      }
      case 'kid': {
        coseKey.set(coseKeyParam, value)
        break
      }
      case 'alg': {
        const coseKeyValue = keyUtils.algorithms.toCOSE.get(value)
        coseKey.set(coseKeyParam, coseKeyValue)
        break
      }
      case 'crv': {
        const coseKeyValue = keyUtils.curves.toCOSE.get(value)
        coseKey.set(coseKeyParam, coseKeyValue)
        break
      }
      case 'x': {
        // TODO: Length checks
        coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
        break
      }
      case 'y': {
        // TODO: Length checks
        coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
        break
      }
      case 'd': {
        // TODO: Length checks
        coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
        break
      }
      default: {
        throw new Error('Unsupported JWK param: ' + key)
      }
    }
  }
  return coseKey
}


export const importJWK = (jwk: Record<string, unknown>): CoseKeyMap => {
  return jwkToCoseKey(jwk)
}