import { decodeFirstSync, toArrayBuffer, encodeAsync, Tagged, Sign1Tag } from '../../cbor'

import { CoseSign1Bytes } from "../sign1";

import { draft_headers } from '../../iana/requested/cose';

export const add = async (signature: CoseSign1Bytes, receipt: CoseSign1Bytes): Promise<ArrayBuffer> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== Sign1Tag) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  if (!(value[1] instanceof Map)) {
    value[1] = new Map();
  }
  // unprotected header
  const receipts = value[1].get(draft_headers.receipts) || []; // see  https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
  receipts.push(receipt)
  value[1].set(draft_headers.receipts, receipts)
  return toArrayBuffer(await encodeAsync(new Tagged(Sign1Tag, value), { canonical: true }));
}