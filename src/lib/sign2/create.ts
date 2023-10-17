import crypto from 'crypto'
import cbor from 'cbor'
import { ec as EC } from 'elliptic' // replace with web crypto / native crypto...

import * as common from '../common'

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

function doSign(SigStructure: any, signer: any, alg: any) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  let ToBeSigned = cbor.encode(SigStructure);
  const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
  hash.update(ToBeSigned);
  ToBeSigned = hash.digest();
  const ec = new EC(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
  const key = ec.keyFromPrivate(signer.key.d);
  const signature = key.sign(ToBeSigned);
  const bitLength = Math.ceil(ec.curve._bitLength / 8);
  return Buffer.concat([signature.r.toArrayLike(Buffer, undefined, bitLength), signature.s.toArrayLike(Buffer, undefined, bitLength)]);
}

export const create = function (headers: any, payload: any, signers: any) {
  let u = headers.u || {};
  let p = headers.p || {};
  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);
  let bodyP = p || {};
  bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  const signer = signers;
  const externalAAD = signer.externalAAD || EMPTY_BUFFER;
  const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
  const SigStructure = [
    'Signature1',
    bodyP,
    externalAAD,
    payload
  ];
  const sig = doSign(SigStructure, signer, alg);
  if (p.size === 0) {
    p = EMPTY_BUFFER;
  } else {
    p = cbor.encode(p);
  }
  const signed = [p, u, payload, sig];
  return cbor.encodeAsync(new Tagged(Sign1Tag, signed), { canonical: true });
};

