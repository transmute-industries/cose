import * as sign1 from "../sign1"

import { decodeFirstSync, encodeAsync, Sign1Tag, Tagged, toArrayBuffer } from '../../cbor'

export const signer = ({ rawSigner }: sign1.RequestCoseSign1Signer) => {
  const coseSign1Signer = sign1.signer({ rawSigner })
  return {
    sign: async (req: sign1.RequestCoseSign1) => {
      const coseSign1 = await coseSign1Signer.sign(req)
      const decoded = decodeFirstSync(coseSign1)
      decoded.value[2] = null
      return encodeAsync(new Tagged(Sign1Tag, decoded.value), { canonical: true })
    }
  }
}

export const verifier = ({ publicKeyJwk }: sign1.RequestCoseSign1Verifier) => {
  const verifier = sign1.verifier({ publicKeyJwk })
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