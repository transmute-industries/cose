
import { PublicKeyJwk } from './types'

import { verifier as coseSign1Verifier } from './lib'

const verifier = async ({ publicKeyJwk }: { publicKeyJwk: PublicKeyJwk }) => {
  return {
    verify: async (message: Uint8Array): Promise<Uint8Array> => {
      const verifiedBuffer = await coseSign1Verifier({ publicKeyJwk }).verify(message as Buffer)
      return new Uint8Array(verifiedBuffer)
    },
  }
}

export default verifier
