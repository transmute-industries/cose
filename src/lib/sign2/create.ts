import crypto from 'crypto'
import cbor from 'cbor'
import { SecretKeyJwk } from './types'
import * as common from '../common'

import getAlgFromVerificationKey from './getAlgFromVerificationKey'

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

const Sign1Tag = exports.Sign1Tag = 18;

const AlgFromTags: any = {};
AlgFromTags[-7] = { sign: 'ES256', digest: 'SHA-256' };
AlgFromTags[-35] = { sign: 'ES384', digest: 'SHA-384' };
AlgFromTags[-36] = { sign: 'ES512', digest: 'SHA-512' };


const COSEAlgToNodeAlg: any = {
  ES256: { sign: 'p256', digest: 'sha256' },
  ES384: { sign: 'p384', digest: 'sha384' },
  ES512: { sign: 'p521', digest: 'sha512' },
};

async function doSign(decodedToBeSigned: any, privateKey: any) {
  const alg = getAlgFromVerificationKey(privateKey)
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
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

