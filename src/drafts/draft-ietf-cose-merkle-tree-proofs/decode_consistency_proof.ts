
import { rfc9162_sha256_proof_types } from '.'
import * as cbor from '../../cbor'
import { draft_headers } from '../../iana/requested/cose'

export const decode_consistency_proof = (receipt: Uint8Array) => {
  const decoded = cbor.decode(receipt)
  if (decoded.tag !== 18) {
    throw new Error('Expected cose-sign1 (tag 18)')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_protectedHeader, unprotectedHeader, _payload, _signature] = decoded.value
  const proofs = unprotectedHeader.get(draft_headers.verifiable_data_proofs)
  const consistency_proofs = proofs.get(rfc9162_sha256_proof_types.consistency)
  return consistency_proofs.map((p: Uint8Array) => {
    const [old_tree_size, new_tree_size, consistency_path] = cbor.decode(p)
    return [old_tree_size, new_tree_size, consistency_path.map((p2: ArrayBuffer) => {
      return new Uint8Array(p2)
    })]
  })
}