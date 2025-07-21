import * as cbor from '../../cbor'
import * as cose from '../../../src'

export const add_receipt = async (signed_statement: Uint8Array, receipt: Uint8Array) => {
    const { value } = cbor.decode(signed_statement)

    // Ensure value[1] is a Map (unprotected header)
    if (value[1] === undefined || !(value[1] instanceof Map)) {
        value[1] = new Map()
    }

    if (value[1].get(cose.draft_headers.receipts) === undefined) {
        value[1].set(cose.draft_headers.receipts, [])
    }
    const current_receipts = value[1].get(cose.draft_headers.receipts)
    // current_receipts = current_receipts.map((r: any) => {
    //   return cbor.toArrayBuffer(cbor.encode(r))
    // })
    current_receipts.push(cbor.toArrayBuffer(receipt))
    // value[1].set(cose.draft_headers.receipts, current_receipts)
    return new Uint8Array(await cbor.encodeAsync(new cbor.Tagged(cose.tag.COSE_Sign1, value), { canonical: true }));
}