import { base64url } from 'jose'
import cose from 'cose-js'
import {
  PrivateKeyJwk,
  ProtectedHeader,
  UnprotectedHeader,
  Payload,
} from './types'

import { typedArrayToBuffer } from './utils'

import { Headers, signer as coseSign1Signer } from './lib'

const signer = async ({ privateKeyJwk }: { privateKeyJwk: PrivateKeyJwk }) => {
  return {
    alg: privateKeyJwk.alg,
    sign: async ({
      protectedHeader,
      unprotectedHeader,
      payload,
    }: {
      protectedHeader: ProtectedHeader
      unprotectedHeader?: UnprotectedHeader
      payload: Payload
    }): Promise<Uint8Array> => {
      const s2 = await coseSign1Signer({ secretKeyJwk: privateKeyJwk }).sign({
        protectedHeader: Headers.TranslateHeaders(protectedHeader),
        unprotectedHeader: unprotectedHeader || new Map(),
        payload: Buffer.from(payload)
      })
      console.log(s2.length)
      const signature = await cose.sign.create(
        { p: protectedHeader, u: unprotectedHeader },
        typedArrayToBuffer(payload),
        {
          key: {
            d: base64url.decode(privateKeyJwk.d),
          },
        },
      )
      console.log(signature.length)
      return new Uint8Array(signature)
    },
  }
}

export default signer
