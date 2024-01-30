import * as cbor from 'cbor-web'

const getContentType = (message: Uint8Array): string => {
  const {
    value: [encodedProtectedHeader],
  } = cbor.decode(message)
  const protectedHeader = cbor.decode(encodedProtectedHeader)
  const contentTypeTag = 3;
  return protectedHeader.get(contentTypeTag)
}

export default getContentType