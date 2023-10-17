import crypto from 'crypto'
import cbor from 'cbor'
import { SecretKeyJwk, DecodedToBeSigned } from './types'
import { Sign1Tag, EMPTY_BUFFER } from './common'

import { HeaderParameters, ProtectedHeaderMap, UnprotectedHeaderMap } from './HeaderParameters';

import getAlgFromVerificationKey from './getAlgFromVerificationKey'

const Tagged = cbor.Tagged;

async function doSign(decodedToBeSigned: DecodedToBeSigned, privateKey: SecretKeyJwk) {
  const encodedToBeSigned = cbor.encode(decodedToBeSigned);
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    privateKey,
    {
      name: "ECDSA",
      namedCurve: privateKey.crv,
    },
    true,
    ["sign"],
  )
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    signingKey,
    encodedToBeSigned,
  );
  return signature
}

export const create = async function (protectedHeaderMap: ProtectedHeaderMap, unprotectedHeaderMap: UnprotectedHeaderMap, payload: Buffer, secretKey: SecretKeyJwk, externalAAD = EMPTY_BUFFER) {
  const signingKeyAlgorithm = getAlgFromVerificationKey(secretKey);
  const envelopeAlgorithm = protectedHeaderMap.get(HeaderParameters.alg) || unprotectedHeaderMap.get(HeaderParameters.alg);
  if (envelopeAlgorithm !== signingKeyAlgorithm) {
    throw new Error('Signing key does not support algorithm: ' + envelopeAlgorithm);
  }
  const protectedHeaderBytes = (protectedHeaderMap.size === 0) ? EMPTY_BUFFER : cbor.encode(protectedHeaderMap);
  const decodedToBeSigned = [
    'Signature1',
    protectedHeaderBytes,
    externalAAD,
    payload
  ] as DecodedToBeSigned;
  const signature = await doSign(decodedToBeSigned, secretKey);
  const coseSign1Structure = [protectedHeaderBytes, unprotectedHeaderMap, payload, signature];
  return cbor.encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true });
};

