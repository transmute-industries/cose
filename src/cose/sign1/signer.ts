
import { encode, encodeAsync, EMPTY_BUFFER, Tagged, toArrayBuffer } from '../../cbor'

import { RequestCoseSign1Signer, RequestCoseSign1, CoseSign1Bytes } from "./types"

import { tag } from '../../iana/assignments/cbor'
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
      return toArrayBuffer(await encodeAsync(new Tagged(tag.COSE_Sign1, coseSign1Structure), { canonical: true }));
    }
  }
}

export default signer