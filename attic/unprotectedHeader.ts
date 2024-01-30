import * as cbor from 'cbor-web'
import { UnprotectedHeader } from './types'

// https://github.com/erdtman/cose-js/blob/master/lib/common.js#L66
const unprotectedHeaderTags = {
  kid: 4,
  content_type: 3,
  counter_signature: 7,

  // will be registered in https://github.com/ietf-scitt/draft-steele-cose-merkle-tree-proofs
  verifiable_data_structure: -111, // 'TBD_1', // int
  verifiable_data_structure_proofs: -222, //'TBD_2', // a map of ints to array of bstrs

  // will be registered in https://datatracker.ietf.org/doc/draft-birkholz-scitt-receipts/
  scitt_receipt: -333, //'TBD_3',
}

const unprotectedHeader = {
  ...unprotectedHeaderTags,
  get: (message: Uint8Array): UnprotectedHeader => {
    const decoded = cbor.decode(message)
    const unprotectedMap = decoded.value[1] as UnprotectedHeader
    return unprotectedMap.size === undefined ? new Map() : unprotectedMap
  },
  set: (message: Uint8Array, unprotectedMap: UnprotectedHeader): Uint8Array => {
    const decoded = cbor.decode(message)
    decoded.value[1] = unprotectedMap
    const updatedMessage = new Uint8Array(cbor.encode(decoded))
    return updatedMessage
  },
}

export default unprotectedHeader
