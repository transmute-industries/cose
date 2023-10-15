import * as cbor from 'cbor-web'

import { DetachedSignature } from './types/DetachedSignature'

import { typedArrayToBuffer } from './utils'

const detachPayload = async (attachedSignature: Uint8Array): Promise<DetachedSignature> => {
  const decoded = cbor.decodeFirstSync(attachedSignature)
  const payload = decoded.value[2]
  decoded.value[2] = typedArrayToBuffer(new Uint8Array())
  cbor.encode(decoded)
  const signature = new Uint8Array(await cbor.encodeAsync(decoded))
  return { payload, signature }
}

export default detachPayload
