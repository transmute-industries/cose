import * as cbor from 'cbor-web'


import { DetachedSignature } from './types/DetachedSignature'

const attachPayload = async ({ payload, signature }: DetachedSignature): Promise<Uint8Array> => {
  const decoded = cbor.decodeFirstSync(signature)
  decoded.value[2] = payload
  return new Uint8Array(await cbor.encodeAsync(decoded))
}

export default attachPayload
