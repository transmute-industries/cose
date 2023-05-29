import { CoMETRE } from '@transmute/rfc9162'

import cbor from '../cbor'
import { RequestConsistencyProofVerification } from '../types'

export const verify_consistency_proof = async ({
  old_root,
  signed_consistency_proof,
  verifier,
}: RequestConsistencyProofVerification) => {
  const decoded = cbor.decode(signed_consistency_proof)
  const [tree_size_1, tree_size_2, consistency_path] = cbor.decode(
    decoded.value[1].get(200),
  )
  const new_root = await verifier.verify(signed_consistency_proof)
  const verified = await CoMETRE.RFC9162_SHA256.verify_consistency_proof(
    old_root,
    new_root,
    {
      log_id: '',
      tree_size_1,
      tree_size_2,
      consistency_path,
    },
  )
  return verified
}
