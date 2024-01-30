import { CoMETRE } from '@transmute/rfc9162'

import cbor from '../cbor'
import { RequestConsistencyProofVerification } from '../types'


import unprotectedHeader from '../unprotectedHeader'

import verifiable_data_structure_proofs from '../verifiable_data_structure_proofs'
export const verify_consistency_proof = async ({
  old_root,
  signed_consistency_proof,
  verifier,
}: RequestConsistencyProofVerification) => {
  const decodedSignedConsistencyProof = cbor.web.decode(signed_consistency_proof)
  const consistencyProofs = decodedSignedConsistencyProof.value[1].get(unprotectedHeader.verifiable_data_structure_proofs)
  const proofs = consistencyProofs.get(verifiable_data_structure_proofs.consistency_proof)
  const [tree_size_1, tree_size_2, consistency_path] = cbor.web.decode(
    proofs[0]
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
