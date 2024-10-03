
import { encode, encodeAsync, EMPTY_BUFFER, Tagged, toArrayBuffer } from '../../cbor'

import { tag } from '../../iana/assignments/cbor'

const signer = ({ remote }: {
  remote: {
    sign: (toBeSigned: Uint8Array) => Promise<Uint8Array>
  }
}) => {
  return {
    sign: async ({ protectedHeader, unprotectedHeader, externalAAD, payload }: {
      protectedHeader: Map<any, any>,
      unprotectedHeader?: Map<any, any>
      externalAAD?: Uint8Array
      payload: Uint8Array
    }): Promise<Uint8Array> => {
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
      return new Uint8Array(await encodeAsync(new Tagged(tag.COSE_Sign1, coseSign1Structure), { canonical: true }));
    }
  }
}

export default signer