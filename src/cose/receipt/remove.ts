import { decodeFirstSync, toArrayBuffer, encodeAsync, Tagged } from '../../cbor'
import { CoseSign1Bytes } from "../sign1";

import * as cbor from '../../iana/assignments/cbor'

export const remove = async (signature: CoseSign1Bytes): Promise<ArrayBuffer> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== cbor.tag.COSE_Sign1) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  value[1] = new Map();
  return toArrayBuffer(await encodeAsync(new Tagged(cbor.tag.COSE_Sign1, value), { canonical: true }));
}