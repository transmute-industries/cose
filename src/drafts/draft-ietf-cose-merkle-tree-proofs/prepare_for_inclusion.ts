
// this function returns a copy of a cose sign1 with no unprotected header
// this enables clients to compute the record hash for any given signed statement


import * as cbor from '../../cbor'
import * as cose from '../../../src'

export const prepare_for_inclusion = async (signed_statement: Uint8Array) => {
  const { value } = cbor.decode(signed_statement)
  value[1] = new Map()
  return new Uint8Array(await cbor.encodeAsync(new cbor.Tagged(cose.tag.COSE_Sign1, value), { canonical: true }));
}