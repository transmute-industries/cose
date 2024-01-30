
import { encode, encodeAsync, EMPTY_BUFFER, Tagged, Sign1Tag } from '../../cbor'

import { RequestCoseSign1Signer, RequestCoseSign1 } from "./types"
import getDigestFromVerificationKey from './getDigestFromVerificationKey'
import subtleCryptoProvider from '../../crypto/subtleCryptoProvider'

const signer = ({ secretKeyJwk }: RequestCoseSign1Signer) => {
  const digest = getDigestFromVerificationKey(`${secretKeyJwk.alg}`)
  return {
    sign: async ({ protectedHeader, unprotectedHeader, externalAAD, payload }: RequestCoseSign1) => {
      const subtle = await subtleCryptoProvider()
      const payloadBuffer = payload
      const protectedHeaderBytes = (protectedHeader.size === 0) ? EMPTY_BUFFER : encode(protectedHeader);
      const decodedToBeSigned = [
        'Signature1',
        protectedHeaderBytes,
        externalAAD || EMPTY_BUFFER,
        payloadBuffer
      ]
      const encodedToBeSigned = encode(decodedToBeSigned);
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
      return encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true });
    }
  }
}

export default signer