
import { rfc9162_sha256_proof_types } from '.'
import * as cbor from '../../cbor'
import { draft_headers } from '../../iana/requested/cose'

export const decode_inclusion_proof = (receipt: Uint8Array) => {
  const decoded = cbor.decode(receipt)
  if (decoded.tag !== 18) {
    throw new Error('Expected cose-sign1 (tag 18)')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_protectedHeader, unprotectedHeader, _payload, _signature] = decoded.value
  const proofs = unprotectedHeader.get(draft_headers.verifiable_data_proofs)
  const inclusion_proofs = proofs.get(rfc9162_sha256_proof_types.inclusion)
  return inclusion_proofs.map((p: Uint8Array) => {
    const [size, index, path] = cbor.decode(p)
    return [size, index, path.map((p2: ArrayBuffer) => {
      return new Uint8Array(p2)
    })]
  })
}