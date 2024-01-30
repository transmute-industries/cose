export const typedArrayToBuffer = (array: Uint8Array): ArrayBuffer => {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}

const utils = { typedArrayToBuffer }

export default utils