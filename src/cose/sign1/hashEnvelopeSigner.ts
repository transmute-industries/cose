import signer from "./signer";

import subtleCryptoProvider from "../../crypto/subtleCryptoProvider";

import { RequestCoseSign1Signer, RequestCoseSign1 } from "./types"

// https://datatracker.ietf.org/doc/draft-steele-cose-hash-envelope/


import { Protected } from "../Params";


export const hash = {
  signer: ({ remote }: RequestCoseSign1Signer) => {
    return {
      sign: async ({ protectedHeader, unprotectedHeader, payload }: RequestCoseSign1): Promise<Uint8Array> => {
        const subtle = await subtleCryptoProvider();
        const hashEnvelopeAlgorithm = protectedHeader.get(Protected.PayloadHashAlgorithm)
        if (hashEnvelopeAlgorithm !== -16) {
          throw new Error('Unsupported hash envelope algorithm (-16 is only one supported)')
        }
        const payloadHash = await subtle.digest("SHA-256", payload)
        const normalSigner = signer({ remote })
        return new Uint8Array(await normalSigner.sign({ protectedHeader, unprotectedHeader, payload: payloadHash }))
      }
    }
  }
}