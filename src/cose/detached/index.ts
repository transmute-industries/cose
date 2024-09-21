import * as sign1 from "../sign1"

import { decodeFirstSync, encodeAsync, Sign1Tag, Tagged, toArrayBuffer } from '../../cbor'
import { UnprotectedHeader } from "../../desugar"

export const signer = ({ remote }: sign1.RequestCoseSign1Signer) => {
  const coseSign1Signer = sign1.signer({ remote })
  return {
    sign: async (req: sign1.RequestCoseSign1) => {
      if (req.unprotectedHeader === undefined) {
        req.unprotectedHeader = UnprotectedHeader([])
      }
      const coseSign1 = await coseSign1Signer.sign(req)
      const decoded = decodeFirstSync(coseSign1)
      decoded.value[2] = null
      return encodeAsync(new Tagged(Sign1Tag, decoded.value), { canonical: true })
    }
  }
}

export const verifier = ({ resolver }: sign1.RequestCoseSign1Verifier) => {
  const verifier = sign1.verifier({ resolver })
  return {
    verify: async (req: sign1.RequestCoseSign1VerifyDetached) => {
      const decoded = decodeFirstSync(req.coseSign1)
      const payloadBuffer = toArrayBuffer(req.payload);
      decoded.value[2] = payloadBuffer
      const attached = await encodeAsync(new Tagged(Sign1Tag, decoded.value), { canonical: true })
      return verifier.verify({ coseSign1: attached })
    }
  }
}