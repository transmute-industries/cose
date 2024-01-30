import { base64url } from 'jose'
import cose from 'cose-js'
import {
  PrivateKeyJwk,
  ProtectedHeader,
  UnprotectedHeader,
  Payload,
} from '../types'

import detachPayload from '../detachPayload'
import { DetachedSignature } from '../types/DetachedSignature'

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
    }): Promise<DetachedSignature> => {
      const signature = await cose.sign.create(
        { p: protectedHeader, u: unprotectedHeader },
        payload,
        {
          key: {
            d: base64url.decode(privateKeyJwk.d),
          },
        },
      )
      return detachPayload(signature)
    },
  }
}

export default signer
