import { decodeFirstSync, Sign1Tag } from '../../cbor'

import { CoseSign1Bytes } from "../sign1";

import { draft_headers } from '../../iana/requested/cose';

export const get = async (signature: CoseSign1Bytes): Promise<CoseSign1Bytes[]> => {
  const { tag, value } = decodeFirstSync(signature)
  if (tag !== Sign1Tag) {
    throw new Error('Receipts can only be added to cose-sign1')
  }
  if (!(value[1] instanceof Map)) {
    return []
  }
  // unprotected header
  const receipts = value[1].get(draft_headers.receipts) || []; // see  https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
  return receipts
}