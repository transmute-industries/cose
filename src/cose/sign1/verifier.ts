
import { decodeFirst, decodeFirstSync, encode, EMPTY_BUFFER } from '../../cbor'
import { RequestCoseSign1Verifier, RequestCoseSign1Verify } from './types'
import getAlgFromVerificationKey from './getAlgFromVerificationKey'
import { DecodedToBeSigned, ProtectedHeaderMap } from './types'
import rawVerifier from '../../crypto/verifier'
import { base64url } from 'jose'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

const ecdsaPublicKeyJwkVerify = async (publicKeyJwk: any, encodedToBeSigned: any, signature: any) => {
  const ecdsa = rawVerifier({ publicKeyJwk })
  return ecdsa.verify(encodedToBeSigned, signature)
}

const mldsaPublicKeyJwkVerifier = async (publicKeyJwk: any, encodedToBeSigned: any, signature: any) => {
  const publicKey = base64url.decode(publicKeyJwk.x)
  return ml_dsa65.verify(publicKey, encodedToBeSigned, signature)
}

const verifier = ({ resolver }: RequestCoseSign1Verifier) => {
  return {
    verify: async ({ coseSign1, externalAAD }: RequestCoseSign1Verify): Promise<ArrayBuffer> => {
      const publicKeyJwk = await resolver.resolve(coseSign1)
      const algInPublicKey = getAlgFromVerificationKey(`${publicKeyJwk.alg}`)
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
      if (algInPublicKey === -49) {
        mldsaPublicKeyJwkVerifier(publicKeyJwk, encodedToBeSigned, signature)
      } else {
        await ecdsaPublicKeyJwkVerify(publicKeyJwk, encodedToBeSigned, signature)
      }
      return payload;
    }
  }
}

export default verifier