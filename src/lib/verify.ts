import crypto from 'crypto'
import * as cbor from 'cbor-web'

import getAlgFromVerificationKey from './getAlgFromVerificationKey'
import getDigestFromVerificationKey from './getDigestFromVerificationKey'
import { AlgFromTags } from './AlgFromTags'
import { PublicKeyJwk, DecodedToBeSigned, CoseSign1Structure } from './types'

import { EMPTY_BUFFER } from './common';

import { labelToTag, ProtectedHeaderMap, getCommonParameter } from './HeaderParameters';

async function doVerify(publicKey: PublicKeyJwk, decodedToBeSigned: DecodedToBeSigned, signature: Buffer) {
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

async function verifyInternal(verificationKey: PublicKeyJwk, signatureStructure: CoseSign1Structure, externalAAD = EMPTY_BUFFER) {
  const verificationKeyAlgorithm = getAlgFromVerificationKey(verificationKey)
  if (!Array.isArray(signatureStructure)) {
    throw new Error('Expecting Array');
  }
  if (signatureStructure.length !== 4) {
    throw new Error('Expecting Array of length 4');
  }
  const [protectedHeaderBytes, unprotectedHeaderMap, plaintext, signature] = signatureStructure;
  const protectedHeaderMap: ProtectedHeaderMap = (!protectedHeaderBytes.length) ? new Map() : cbor.decodeFirstSync(protectedHeaderBytes);
  const envelopeAlgorithm = getCommonParameter(protectedHeaderMap, unprotectedHeaderMap, labelToTag.get('alg'))
  if (envelopeAlgorithm !== verificationKeyAlgorithm) {
    throw new Error('Verification key does not support algorithm: ' + envelopeAlgorithm);
  }
  if (!AlgFromTags[envelopeAlgorithm]) {
    throw new Error('Unknown algorithm, ' + envelopeAlgorithm);
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

export const verify = async function (payload: Buffer, verificationKey: PublicKeyJwk) {
  const obj = await cbor.decodeFirst(payload);
  return verifyInternal(verificationKey, obj.value);
};
