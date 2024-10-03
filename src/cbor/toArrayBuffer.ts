export const toArrayBuffer = (array: Uint8Array | ArrayBuffer): ArrayBuffer => {
  if (array instanceof ArrayBuffer) {
    return array
  }
  if (array instanceof Uint8Array) {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
  }
  throw new Error('Unsupported buffer type')

}