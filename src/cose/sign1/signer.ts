
import { encode, encodeAsync, EMPTY_BUFFER, Tagged, Sign1Tag, toArrayBuffer } from '../../cbor'

import { RequestCoseSign1Signer, RequestCoseSign1, CoseSign1Bytes } from "./types"


const signer = ({ remote }: RequestCoseSign1Signer) => {
  return {
    sign: async ({ protectedHeader, unprotectedHeader, externalAAD, payload }: RequestCoseSign1): Promise<CoseSign1Bytes> => {
      // assume the caller does not realize that cbor will preserve the the View Type, and remove it.
      const payloadBuffer = toArrayBuffer(payload);
      const protectedHeaderBytes = (protectedHeader.size === 0) ? EMPTY_BUFFER : encode(protectedHeader);
      const decodedToBeSigned = [
        'Signature1',
        protectedHeaderBytes,
        externalAAD || EMPTY_BUFFER,
        payloadBuffer
      ]
      const encodedToBeSigned = encode(decodedToBeSigned);
      const signature = await remote.sign(encodedToBeSigned)
      const coseSign1Structure = [protectedHeaderBytes, unprotectedHeader, payloadBuffer, signature];
      return toArrayBuffer(await encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true }));
    }
  }
}

export default signer