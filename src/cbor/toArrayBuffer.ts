import { Buffer } from 'buffer'

export const toArrayBuffer = (array: Uint8Array | ArrayBuffer | any): ArrayBuffer => {
    // Handle null and undefined
    if (array === null || array === undefined) {
        return new ArrayBuffer(0)
    }

    if (array instanceof ArrayBuffer) {
        return array
    }
    if (array instanceof Uint8Array) {
        return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
    }
    // Handle Buffer type (Node.js Buffer)
    if (array && typeof array === 'object' && array.buffer && typeof array.byteOffset === 'number' && typeof array.byteLength === 'number') {
        return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
    }
    throw new Error('Unsupported buffer type')
}