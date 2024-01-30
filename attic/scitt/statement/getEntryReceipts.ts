
import cbor from '../../cbor'

import { default as tags } from '../../unprotectedHeader'

type RequestEntryReceipts = {
  transparentStatement: ArrayBuffer
}

export const getEntryReceipts = ({ transparentStatement }: RequestEntryReceipts) => {
  const decoded = cbor.decode(transparentStatement)
  let unprotectedHeader = decoded.value[1]
  if (!(unprotectedHeader instanceof Map)) {
    unprotectedHeader = new Map()
  }
  const receipts = unprotectedHeader.get(tags.scitt_receipt) || []
  decoded.value[1] = new Map()
  const entry = cbor.encode(decoded)
  return { entry, receipts }
}

