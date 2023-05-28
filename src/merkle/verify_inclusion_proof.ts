import { CoMETRE } from '@transmute/rfc9162'

import cbor from '../cbor'
import { RequestInclusionProofVerification } from '../types'
import attachPayload from '../attachPayload'
export const verify_inclusion_proof = async ({
  leaf,
  signed_inclusion_proof,
  verifier,
}: RequestInclusionProofVerification) => {
  const decoded = cbor.decode(signed_inclusion_proof)
  const [log_id, tree_size, leaf_index, inclusion_path] = cbor.decode(
    decoded.value[1].get(100),
  )
  const validated_root = await CoMETRE.RFC9162_SHA256.verify_inclusion_proof(
    leaf,
    {
      log_id,
      tree_size,
      leaf_index,
      inclusion_path,
    },
  )
  if (validated_root === false) {
    return false
  }
  const attached = attachPayload(signed_inclusion_proof, validated_root)
  const verified_root = await verifier.verify(attached)
  if (verified_root) {
    // console.log(verified_root)
    return true
  }
  return false
}
