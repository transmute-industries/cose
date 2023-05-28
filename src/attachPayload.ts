import * as cbor from 'cbor-web'

const attachPayload = (message: Uint8Array, payload: Uint8Array) => {
  const decoded = cbor.decode(message)
  decoded.value[2] = payload
  return cbor.encode(decoded)
}

export default attachPayload
