
import * as cbor from '../../cbor'
type old_tree_size = number
type new_tree_size = number
type consistency_path = Uint8Array[]
type consistency_proof = [old_tree_size, new_tree_size, consistency_path]
type encoded_consistency_proof = ArrayBuffer

export const encode_consistency_proof = (proof: consistency_proof): encoded_consistency_proof => {
  const [old_tree_size, new_tree_size, consistency_path] = proof
  return cbor.toArrayBuffer(cbor.encode([old_tree_size, new_tree_size, consistency_path.map((p) => {
    return cbor.toArrayBuffer(p)
  })]))
}