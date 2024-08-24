import { decodeFirstSync, Sign1Tag } from '../../cbor'
import { Receipts } from '../Params';
import { CoseSign1Bytes } from "../sign1";

export const get = async (signature: CoseSign1Bytes): Promise<CoseSign1Bytes[]> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== Sign1Tag) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  if (!(value[1] instanceof Map)) {
    return []
  }
  // unprotected header
  const receipts = value[1].get(Receipts) || []; // see  https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
  return receipts
}