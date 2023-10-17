import crypto from 'crypto'
import cbor from 'cbor'
import { ec as EC } from 'elliptic' // replace with web crypto / native crypto...

import * as common from '../common'

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

const SignTag = exports.SignTag = 98;
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

function doVerify(SigStructure: any, verifier: any, alg: any, sig: any) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  const nodeAlg = COSEAlgToNodeAlg[AlgFromTags[alg].sign];
  if (!nodeAlg) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  if (AlgFromTags[alg].sign.startsWith('ES')) {
    const hash = crypto.createHash(nodeAlg.digest);
    hash.update(ToBeSigned);
    const msgHash = hash.digest();

    const pub = { x: verifier.key.x, y: verifier.key.y };
    const ec = new EC(nodeAlg.sign);
    const key = ec.keyFromPublic(pub);
    sig = { r: sig.slice(0, sig.length / 2), s: sig.slice(sig.length / 2) };
    if (!key.verify(msgHash, sig)) {
      throw new Error('Signature missmatch');
    }
  } else {
    const verify = crypto.createVerify(nodeAlg.sign);
    verify.update(ToBeSigned);
    if (!verify.verify(verifier.key, sig)) {
      throw new Error('Signature missmatch');
    }
  }
}

function getSigner(signers: any, verifier: any) {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter(first: any, second: any, parameter: any) {
  let result;
  if (first.get) {
    result = first.get(parameter);
  }
  if (!result && second.get) {
    result = second.get(parameter);
  }
  return result;
}

export const verify = async function (payload: any, verifier: any, options: any = {}) {
  options = options || {};
  const obj = await cbor.decodeFirst(payload);
  return verifyInternal(verifier, options, obj);
};

export const verifySync = function (payload: any, verifier: any, options: any) {
  options = options || {};
  const obj = cbor.decodeFirstSync(payload);
  return verifyInternal(verifier, options, obj);
};

function verifyInternal(verifier: any, options: any, obj: any) {
  options = options || {};
  let type = options.defaultType ? options.defaultType : SignTag;
  if (obj instanceof Tagged) {
    if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }

  // eslint-disable-next-line prefer-const
  let [p, u, plaintext, signers] = obj;

  if (type === SignTag && !Array.isArray(signers)) {
    throw new Error('Expecting signature Array');
  }

  p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  u = (!u.size) ? EMPTY_BUFFER : u;

  const signer = (type === SignTag ? getSigner(signers, verifier) : signers);

  if (!signer) {
    throw new Error('Failed to find signer with kid' + verifier.key.kid);
  }

  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    // eslint-disable-next-line prefer-const
    let [signerP, , sig] = signer;
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const signerPMap = cbor.decode(signerP);
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature',
      p,
      signerP,
      externalAAD,
      plaintext
    ];
    doVerify(SigStructure, verifier, alg, sig);
    return plaintext;
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

    const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const SigStructure = [
      'Signature1',
      p,
      externalAAD,
      plaintext
    ];
    doVerify(SigStructure, verifier, alg, signer);
    return plaintext;
  }
}
