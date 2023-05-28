import * as cbor from 'cbor-web'

const detachPayload = (message: Uint8Array) => {
  const decoded = cbor.decode(message)
  const payload = decoded.value[2]
  decoded.value[2] = new Uint8Array()
  cbor.encode(decoded)
  return { payload, signed: cbor.encode(decoded) }
}

export default detachPayload
