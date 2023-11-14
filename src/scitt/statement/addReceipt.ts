
import cbor from '../../cbor'

import { default as tags } from '../../unprotectedHeader'

type RequestAddReceipt = {
  statement: ArrayBuffer // really signed statement
  receipt: ArrayBuffer
}

export const addReceipt = ({ statement, receipt }: RequestAddReceipt) => {
  const decoded = cbor.decode(statement)
  let unprotectedHeader = decoded.value[1]
  if (!(unprotectedHeader instanceof Map)) {
    unprotectedHeader = new Map()
  }
  const existingReceipts = unprotectedHeader.get(tags.scitt_receipt)
  if (!existingReceipts) {
    unprotectedHeader.set(tags.scitt_receipt, [receipt])
  } else {
    existingReceipts.push(receipt)
  }
  decoded.value[1] = unprotectedHeader
  return cbor.encode(decoded)
}

