import * as cbor from 'cbor-web'


import { DetachedSignature } from './types/DetachedSignature'

import { typedArrayToBuffer } from './utils'

const attachPayload = async ({ payload, signature }: DetachedSignature): Promise<Uint8Array> => {
  const decoded = cbor.decodeFirstSync(signature)
  decoded.value[2] = typedArrayToBuffer(payload)
  return new Uint8Array(await cbor.encodeAsync(decoded))
}

export default attachPayload
