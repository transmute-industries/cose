import cbor from "./cbor"
import { EMPTY_BUFFER } from './lib/common'

export const extractTBS = (message: Uint8Array) => {
  const { tag, value } = cbor.decode(message)
  if (tag !== 18) {
    throw new Error('only cose sign 1 is supported')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [protectedHeaderBytes, unprotectedHeaderMap, payloadBuffer] = value
  const tbs = cbor.encode([
    'Signature1',
    protectedHeaderBytes,
    EMPTY_BUFFER,
    payloadBuffer
  ]);
  return tbs
}