import { base64url } from 'jose'
import cose from 'cose-js'

import { PublicKeyJwk } from '../types'
import attachPayload from '../attachPayload'


type RequestDetachedVerify = {
  payload: Uint8Array
  signature: Uint8Array //detached payload cose sign1
}

const verifier = async ({ publicKeyJwk }: { publicKeyJwk: PublicKeyJwk }) => {
  return {
    verify: async ({ payload, signature }: RequestDetachedVerify): Promise<boolean> => {
      const message = await attachPayload({
        payload, signature
      })
      try {
        await cose.sign.verify(message, {
          key: {
            x: base64url.decode(publicKeyJwk.x),
            y: base64url.decode(publicKeyJwk.y),
          },
        })
        return true
      } catch (e) {
        // console.error((e as any).message)
      }
      return false
    },
  }
}

export default verifier
