import * as cbor from 'cbor-web'

const getContentType = (message: Uint8Array): string => {
  const {
    value: [encodedProtectedHeader],
  } = cbor.decode(message)
  const protectedHeader = cbor.decode(encodedProtectedHeader)
  const contentTypeTag = protectedHeader.get(3)
  return new TextDecoder().decode(contentTypeTag)
}

export default getContentType