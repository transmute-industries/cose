import { decodeFirstSync, toArrayBuffer, encodeAsync, Tagged, Sign1Tag } from '../../cbor'
import { CoseSign1Bytes } from "../sign1";

export const remove = async (signature: CoseSign1Bytes): Promise<ArrayBuffer> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== Sign1Tag) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  value[1] = new Map();
  return toArrayBuffer(await encodeAsync(new Tagged(Sign1Tag, value), { canonical: true }));
}