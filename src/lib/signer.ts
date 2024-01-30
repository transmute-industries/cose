
import * as cbor from 'cbor-web'

import { EMPTY_BUFFER, Tagged, Sign1Tag } from './common'
import { RequestCoseSign1Signer, RequestCoseSign1 } from "./types"
import getDigestFromVerificationKey from './getDigestFromVerificationKey'

import subtleCryptoProvider from '../crypto/subtleCryptoProvider'


const signer = ({ secretKeyJwk }: RequestCoseSign1Signer) => {
  const digest = getDigestFromVerificationKey(secretKeyJwk)
  return {
    sign: async ({ protectedHeader, unprotectedHeader, externalAAD, payload }: RequestCoseSign1) => {
      const subtle = await subtleCryptoProvider()
      const payloadBuffer = payload
      const protectedHeaderBytes = (protectedHeader.size === 0) ? EMPTY_BUFFER : cbor.encode(protectedHeader);
      const decodedToBeSigned = [
        'Signature1',
        protectedHeaderBytes,
        externalAAD || EMPTY_BUFFER,
        payloadBuffer
      ]
      const encodedToBeSigned = cbor.encode(decodedToBeSigned);
      const signingKey = await subtle.importKey(
        "jwk",
        secretKeyJwk,
        {
          name: "ECDSA",
          namedCurve: secretKeyJwk.crv,
        },
        true,
        ["sign"],
      )
      const signature = await subtle.sign(
        {
          name: "ECDSA",
          hash: { name: digest },
        },
        signingKey,
        encodedToBeSigned,
      );
      const coseSign1Structure = [protectedHeaderBytes, unprotectedHeader, payloadBuffer, signature];
      return cbor.encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true });
    }
  }
}

export default signer