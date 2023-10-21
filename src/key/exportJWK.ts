import { CoseKeyMap } from "./types";
import * as jose from 'jose'
import keyUtils from './keyUtils'

const sortJwk = (jwk: any) => {
  const { kty, kid, alg, crv, x, y, d, ...rest } = jwk
  return JSON.parse(JSON.stringify({ kty, kid, alg, crv, x, y, d, ...rest }))
}

const coseKeyToJwk = (coseKey: CoseKeyMap): Record<string, unknown> => {
  const jwk = {} as any;
  for (const [key, value] of coseKey.entries()) {
    switch (key) {
      case 1: {
        const kty = keyUtils.types.toJOSE.get(value as number)
        jwk.kty = kty
        break
      }
      case 2: {
        jwk.kid = value
        break
      }
      case 3: {
        const alg = keyUtils.algorithms.toJOSE.get(value as number)
        jwk.alg = alg
        break
      }
      case -1: {
        const crv = keyUtils.curves.toJOSE.get(value as number)
        jwk.crv = crv
        break
      }
      case -2: {
        // TODO: Length checks
        jwk.x = jose.base64url.encode(value as Buffer)
        break
      }
      case -3: {
        // TODO: Length checks
        jwk.y = jose.base64url.encode(value as Buffer)
        break
      }
      case -4: {
        // TODO: Length checks
        jwk.d = jose.base64url.encode(value as Buffer)
        break
      }
      default: {
        // throw new Error('Unsupported JWK param: ' + key)
      }
    }
  }
  return sortJwk(jwk)
}

export const exportJWK = (coseKey: CoseKeyMap): Record<string, unknown> => {
  return coseKeyToJwk(coseKey)
}