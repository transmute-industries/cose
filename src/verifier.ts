import { base64url } from 'jose'
import cose from 'cose-js'

import { PublicKeyJwk } from './types'
const verifier = async ({ publicKeyJwk }: { publicKeyJwk: PublicKeyJwk }) => {
  return {
    verify: async (message: Uint8Array): Promise<Uint8Array> => {
      const buf = await cose.sign.verify(message, {
        key: {
          x: base64url.decode(publicKeyJwk.x),
          y: base64url.decode(publicKeyJwk.y),
        },
      })
      return new Uint8Array(buf)
    },
  }
}

export default verifier
