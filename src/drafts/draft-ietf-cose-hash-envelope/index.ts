
import * as cose from '../../iana/assignments/cose'

import { draft_headers } from '../../iana/requested/cose'

import signer from "../../cose/sign1/signer";

import subtleCryptoProvider from "../../crypto/subtle";


export const hash = {
  signer: ({ remote }: {
    remote: {
      sign: (toBeSigned: Uint8Array) => Promise<Uint8Array>
    }
  }) => {
    return {
      sign: async ({ protectedHeader, unprotectedHeader, payload }: {
        protectedHeader: Map<any, any>
        unprotectedHeader?: Map<any, any>
        payload: Uint8Array
      }): Promise<Uint8Array> => {
        const subtle = await subtleCryptoProvider();
        const hashEnvelopeAlgorithm = protectedHeader.get(draft_headers.payload_hash_algorithm)
        if (hashEnvelopeAlgorithm !== cose.algorithm.sha_256) {
          throw new Error('Unsupported hash envelope algorithm (-16 is only one supported)')
        }
        const payloadHash = new Uint8Array(await subtle.digest("SHA-256", payload))
        const normalSigner = signer({ remote })
        return new Uint8Array(await normalSigner.sign({ protectedHeader, unprotectedHeader, payload: payloadHash }))
      }
    }
  }
}