import * as cbor from 'cbor-web'

const getKid = (message: Uint8Array): string => {
  const {
    value: [encodedProtectedHeader],
  } = cbor.decode(message)
  const protectedHeader = cbor.decode(encodedProtectedHeader)
  const kidTag = protectedHeader.get(4)
  const kid = new TextDecoder().decode(kidTag)
  return kid
}

export default getKid