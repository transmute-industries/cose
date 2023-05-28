import { base64url } from 'jose'
import cose from 'cose-js'
import {
  PrivateKeyJwk,
  ProtectedHeader,
  UnprotectedHeader,
  Payload,
} from './types'

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
      const signature = await cose.sign.create(
        { p: protectedHeader, u: unprotectedHeader },
        payload,
        {
          key: {
            d: base64url.decode(privateKeyJwk.d),
          },
        },
      )
      return new Uint8Array(signature)
    },
  }
}

export default signer
