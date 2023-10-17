import crypto from 'crypto'
import cbor from 'cbor'
import { SecretKeyJwk } from './types'
import * as common from '../common'

import getAlgFromVerificationKey from './getAlgFromVerificationKey'

import { AlgFromTags } from './AlgFromTags'

export const Sign1Tag = 18;

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

async function doSign(decodedToBeSigned: any, privateKey: any) {
  const alg = getAlgFromVerificationKey(privateKey)
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }

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

export const create = async function (protectedHeaderMap: Map<any, any>, unprotectedHeaderMaop: Map<any, any>, payload: Buffer, secretKey: SecretKeyJwk, externalAAD = EMPTY_BUFFER) {
  const signingKeyAlgorithm = getAlgFromVerificationKey(secretKey);
  const envelopeAlgorithm = protectedHeaderMap.get(common.HeaderParameters.alg) || unprotectedHeaderMaop.get(common.HeaderParameters.alg);
  const protectedHeaderBytes = (protectedHeaderMap.size === 0) ? EMPTY_BUFFER : cbor.encode(protectedHeaderMap);
  if (envelopeAlgorithm !== signingKeyAlgorithm) {
    throw new Error('Signing key does not support algorithm: ' + envelopeAlgorithm);
  }
  const SigStructure = [
    'Signature1',
    protectedHeaderBytes,
    externalAAD,
    payload
  ];
  const sig = await doSign(SigStructure, secretKey);
  const signed = [protectedHeaderBytes, unprotectedHeaderMaop, payload, sig];
  return cbor.encodeAsync(new Tagged(Sign1Tag, signed), { canonical: true });
};

