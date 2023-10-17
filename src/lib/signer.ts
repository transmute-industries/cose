import crypto from 'crypto'

import * as cbor from 'cbor-web'

import { EMPTY_BUFFER, Tagged, Sign1Tag } from './common'
import { RequestCoseSign1Signer, RequestCoseSign1 } from "./types"
import getDigestFromVerificationKey from './getDigestFromVerificationKey'

const signer = ({ secretKeyJwk }: RequestCoseSign1Signer) => {
  const digest = getDigestFromVerificationKey(secretKeyJwk)
  return {
    sign: async ({ protectedHeader, unprotectedHeader, externalAAD, payload }: RequestCoseSign1) => {
      const protectedHeaderBytes = (protectedHeader.size === 0) ? EMPTY_BUFFER : cbor.encode(protectedHeader);
      const encodedToBeSigned = cbor.encode([
        'Signature1',
        protectedHeaderBytes,
        externalAAD || EMPTY_BUFFER,
        payload
      ]);
      const signingKey = await crypto.subtle.importKey(
        "jwk",
        secretKeyJwk,
        {
          name: "ECDSA",
          namedCurve: secretKeyJwk.crv,
        },
        true,
        ["sign"],
      )
      const signature = await crypto.subtle.sign(
        {
          name: "ECDSA",
          hash: { name: digest },
        },
        signingKey,
        encodedToBeSigned,
      );
      const coseSign1Structure = [protectedHeaderBytes, unprotectedHeader, payload, signature];
      return cbor.encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true });
    }
  }
}

export default signer