import { decodeFirstSync, toArrayBuffer, encodeAsync, Tagged, Sign1Tag } from '../../cbor'
import { Receipts } from '../Params';
import { CoseSign1Bytes } from "../sign1";

export const add = async (signature: CoseSign1Bytes, receipt: CoseSign1Bytes): Promise<ArrayBuffer> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== Sign1Tag) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  if (!(value[1] instanceof Map)) {
    value[1] = new Map();
  }
  // unprotected header
  const receipts = value[1].get(Receipts) || []; // see  https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
  receipts.push(receipt)
  value[1].set(Receipts, receipts)
  return toArrayBuffer(await encodeAsync(new Tagged(Sign1Tag, value), { canonical: true }));
}