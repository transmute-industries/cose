
import { decodeFirst, decodeFirstSync, encode, EMPTY_BUFFER } from '../../cbor'

import { RequestCoseSign1Verifier, CoseSign1Bytes, RequestCoseSign1Verify } from './types'

import getAlgFromVerificationKey from './getAlgFromVerificationKey'
import getDigestFromVerificationKey from './getDigestFromVerificationKey'

import { DecodedToBeSigned, ProtectedHeaderMap } from './types'

import subtleCryptoProvider from '../../crypto/subtleCryptoProvider'

const verifier = ({ publicKeyJwk }: RequestCoseSign1Verifier) => {
  const algInPublicKey = getAlgFromVerificationKey(`${publicKeyJwk.alg}`)
  const digest = getDigestFromVerificationKey(`${publicKeyJwk.alg}`)
  return {
    verify: async ({ coseSign1, externalAAD }: RequestCoseSign1Verify): Promise<Buffer> => {
      const subtle = await subtleCryptoProvider()
      const obj = await decodeFirst(coseSign1);
      const signatureStructure = obj.value;
      if (!Array.isArray(signatureStructure)) {
        throw new Error('Expecting Array');
      }
      if (signatureStructure.length !== 4) {
        throw new Error('Expecting Array of length 4');
      }
      const [protectedHeaderBytes, _, payload, signature] = signatureStructure;
      const protectedHeaderMap: ProtectedHeaderMap = (!protectedHeaderBytes.length) ? new Map() : decodeFirstSync(protectedHeaderBytes);
      const algInHeader = protectedHeaderMap.get(1)
      if (algInHeader !== algInPublicKey) {
        throw new Error('Verification key does not support algorithm: ' + algInHeader);
      }
      if (!signature) {
        throw new Error('No signature to verify');
      }
      const decodedToBeSigned = [
        'Signature1',
        protectedHeaderBytes,
        externalAAD || EMPTY_BUFFER,
        payload
      ] as DecodedToBeSigned
      const encodedToBeSigned = encode(decodedToBeSigned);
      const verificationKey = await subtle.importKey(
        "jwk",
        publicKeyJwk,
        {
          name: "ECDSA",
          namedCurve: publicKeyJwk.crv,
        },
        true,
        ["verify"],
      )
      const verified = await subtle.verify(
        {
          name: "ECDSA",
          hash: { name: digest },
        },
        verificationKey,
        signature,
        encodedToBeSigned,
      );
      if (!verified) {
        throw new Error('Signature verification failed');
      }
      return payload;
    }
  }
}

export default verifier