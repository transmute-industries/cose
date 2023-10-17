import crypto from 'crypto'
import cbor from 'cbor'

import * as common from '../common'
import getCommonParameter from './getCommonParameter';
import { VerifierKeyJwk } from './VerifierKeyJwk'
import getAlgFromVerificationKey from './getAlgFromVerificationKey'
import getDigestFromVerificationKey from './getDigestFromVerificationKey'

export const Sign1Tag = 18;

const EMPTY_BUFFER = common.EMPTY_BUFFER;

export type AlgorithmSummary = {
  alg: string
  digest: string
  crv: string
}
const AlgFromTags: Record<number, AlgorithmSummary> = {};
AlgFromTags[-7] = { alg: 'ES256', digest: 'SHA-256', crv: 'P-256' };
AlgFromTags[-35] = { alg: 'ES384', digest: 'SHA-384', crv: 'P-384' };
AlgFromTags[-36] = { alg: 'ES512', digest: 'SHA-512', crv: 'P-521' };

export type UnprotectedHeaderMap = Map<string | number, any>
export type CoseSign1Structure = [Buffer, UnprotectedHeaderMap, Buffer, Buffer]
export type DecodedToBeSigned = [string, Buffer, Buffer, Buffer]
export type DecodedCoseSign1 = {
  value: CoseSign1Structure
}

async function doVerify(publicKey: VerifierKeyJwk, decodedToBeSigned: DecodedToBeSigned, signature: Buffer) {
  const digest = getDigestFromVerificationKey(publicKey)
  const encodedToBeSigned = cbor.encode(decodedToBeSigned);
  const verificationKey = await crypto.subtle.importKey(
    "jwk",
    publicKey,
    {
      name: "ECDSA",
      namedCurve: publicKey.crv,
    },
    true,
    ["verify"],
  )
  const verified = await crypto.subtle.verify(
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
}

async function verifyInternal(verificationKey: VerifierKeyJwk, signatureStructure: CoseSign1Structure, externalAAD = EMPTY_BUFFER) {
  const verificationKeyAlgorithm = getAlgFromVerificationKey(verificationKey)
  if (!Array.isArray(signatureStructure)) {
    throw new Error('Expecting Array');
  }
  if (signatureStructure.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }
  const [protectedHeaderBytes, unprotectedHeaderMap, plaintext, signature] = signatureStructure;
  const protectedHeaderMap = (!protectedHeaderBytes.length) ? new Map() : cbor.decodeFirstSync(protectedHeaderBytes);
  const alg = getCommonParameter(protectedHeaderMap, unprotectedHeaderMap, common.HeaderParameters.alg)
  if (alg !== verificationKeyAlgorithm) {
    throw new Error('Verification key does not support algorithm: ' + alg);
  }
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!signature) {
    throw new Error('No signature to verify');
  }
  const decodedToBeSigned = [
    'Signature1',
    protectedHeaderBytes,
    externalAAD,
    plaintext
  ] as DecodedToBeSigned
  await doVerify(verificationKey, decodedToBeSigned, signature);
  return plaintext;
}

export const verify = async function (payload: Buffer, verificationKey: VerifierKeyJwk) {
  const obj = await cbor.decodeFirst(payload);
  return verifyInternal(verificationKey, obj.value);
};
