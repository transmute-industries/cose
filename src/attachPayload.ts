import * as cbor from 'cbor-web'


import { DetachedSignature } from './types/DetachedSignature'

const attachPayload = ({ payload, signature }: DetachedSignature): Uint8Array => {
  const decoded = cbor.decode(signature)
  decoded.value[2] = payload
  return new Uint8Array(cbor.encode(decoded))
}

export default attachPayload
