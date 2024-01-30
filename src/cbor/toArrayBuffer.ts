export const toArrayBuffer = (array: Uint8Array | ArrayBuffer): ArrayBuffer => {
  if (array instanceof ArrayBuffer) {
    return array
  }
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}