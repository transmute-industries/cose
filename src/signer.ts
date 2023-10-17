
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
      const coseSign1 = await coseSign1Signer({ secretKeyJwk: privateKeyJwk }).sign({
        protectedHeader: Headers.TranslateHeaders(protectedHeader),
        unprotectedHeader: unprotectedHeader || new Map(),
        payload: typedArrayToBuffer(payload) as Buffer
      })
      return new Uint8Array(coseSign1)
    },
  }
}

export default signer
