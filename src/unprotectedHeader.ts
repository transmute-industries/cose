import * as cbor from 'cbor-web'
import { UnprotectedHeader } from './types'

const unprotectedHeaderTags = {
  kid: 4,
  counter_signature: 7,
  // will be registered in https://github.com/ietf-scitt/draft-steele-cose-merkle-tree-proofs
  inclusion_proof: 100,
  consistency_proof: 200,
}

const unprotectedHeader = {
  ...unprotectedHeaderTags,
  set: (message: Uint8Array, updated: UnprotectedHeader) => {
    const decoded = cbor.decode(message)
    decoded.value[1] = updated
    return cbor.encode(decoded)
  },
}

export default unprotectedHeader
