
import * as cbor from '../../cbor'
type tree_size = number
type record_index = number
type inclusion_path = Uint8Array[]
type inclusion_proof = [tree_size, record_index, inclusion_path]
type encoded_inclusion_proof = ArrayBuffer

export const encode_inclusion_proof = (proof: inclusion_proof): encoded_inclusion_proof => {
  const [size, index, path] = proof
  return cbor.toArrayBuffer(cbor.encode([size, index, path.map((p) => {
    return cbor.toArrayBuffer(p)
  })]))
}