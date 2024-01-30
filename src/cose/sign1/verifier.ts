

import * as cbor from 'cbor-web'

import { RequestCoseSign1Verifier, CoseSign1Bytes } from './types'

import getAlgFromVerificationKey from './getAlgFromVerificationKey'
import getDigestFromVerificationKey from './getDigestFromVerificationKey'

import { DecodedToBeSigned } from './types'


import { EMPTY_BUFFER } from './common'

import subtleCryptoProvider from '../../crypto/subtleCryptoProvider'

const verifier = ({ publicKeyJwk }: RequestCoseSign1Verifier) => {
  const algInPublicKey = getAlgFromVerificationKey(`${publicKeyJwk.alg}`)
  const digest = getDigestFromVerificationKey(`${publicKeyJwk.alg}`)
  return {
    verify: async (coseSign1Bytes: CoseSign1Bytes, externalAAD = EMPTY_BUFFER): Promise<Buffer> => {
      const subtle = await subtleCryptoProvider()
      const obj = await cbor.decodeFirst(coseSign1Bytes);
      const signatureStructure = obj.value;
      if (!Array.isArray(signatureStructure)) {
        throw new Error('Expecting Array');
      }
      if (signatureStructure.length !== 4) {
        throw new Error('Expecting Array of length 4');
      }
      const [protectedHeaderBytes, _, payload, signature] = signatureStructure;
      const protectedHeaderMap: Map<any, any> = (!protectedHeaderBytes.length) ? new Map() : cbor.decodeFirstSync(protectedHeaderBytes);
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
        externalAAD,
        payload
      ] as DecodedToBeSigned
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
      const encodedToBeSigned = cbor.encode(decodedToBeSigned);
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