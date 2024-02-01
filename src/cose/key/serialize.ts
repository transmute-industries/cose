
import { encode } from '../../cbor'
import { JWK } from 'jose'
import { CoseKey } from '.'

export const serialize = <T>(key: JWK | CoseKey) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if ((key as any).kty) {
    return JSON.stringify(key, null, 2)
  }
  return encode(key)
}