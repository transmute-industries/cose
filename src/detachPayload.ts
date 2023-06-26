import * as cbor from 'cbor-web'

import { DetachedSignature } from './types/DetachedSignature'

const detachPayload = (attachedSignature: Uint8Array): DetachedSignature => {
  const decoded = cbor.decode(attachedSignature)
  const payload = decoded.value[2]
  decoded.value[2] = new Uint8Array()
  cbor.encode(decoded)
  const signature = new Uint8Array(cbor.encode(decoded))
  return { payload, signature }
}

export default detachPayload
