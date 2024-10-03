
import { decodeFirst, decodeFirstSync, encode, EMPTY_BUFFER, toArrayBuffer } from '../../cbor'



import rawVerifier from '../../crypto/verifier'

import { HeaderMap } from '../../desugar'

import * as cose from '../../iana/assignments/cose'
import { algorithms_to_labels } from '../../iana/requested/cose'

const verifier = ({ resolver }: {
  resolver: {
    resolve: (signature: Uint8Array) => Promise<any>
  }
}) => {
  return {
    verify: async ({ coseSign1, externalAAD }: {
      coseSign1: Uint8Array,
      externalAAD?: Uint8Array
    }): Promise<Uint8Array> => {
      const publicKeyJwk = await resolver.resolve(coseSign1)
      const algInPublicKey = algorithms_to_labels.get(publicKeyJwk.alg as string)
      const ecdsa = rawVerifier({ publicKeyJwk })
      const obj = await decodeFirst(coseSign1);
      const signatureStructure = obj.value;
      if (!Array.isArray(signatureStructure)) {
        throw new Error('Expecting Array');
      }
      if (signatureStructure.length !== 4) {
        throw new Error('Expecting Array of length 4');
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const [protectedHeaderBytes, _, payload, signature] = signatureStructure;
      const protectedHeaderMap: HeaderMap = (!protectedHeaderBytes.length) ? new Map() : decodeFirstSync(protectedHeaderBytes);
      const algInHeader = protectedHeaderMap.get(cose.header.alg)
      if (algInHeader !== algInPublicKey) {
        throw new Error('Verification key does not support algorithm: ' + algInHeader);
      }
      if (!signature) {
        throw new Error('No signature to verify');
      }
      // be careful with Uint8Array near cbor encode... because of aggresive tagging
      const decodedToBeSigned: [string, ArrayBuffer, ArrayBuffer, ArrayBuffer] = [
        'Signature1',
        toArrayBuffer(protectedHeaderBytes),
        toArrayBuffer(externalAAD || EMPTY_BUFFER),
        toArrayBuffer(payload)
      ]
      const encodedToBeSigned = encode(decodedToBeSigned);
      await ecdsa.verify(encodedToBeSigned, signature)
      return payload;
    }
  }
}

export default verifier