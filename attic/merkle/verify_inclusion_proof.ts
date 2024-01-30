import { CoMETRE } from '@transmute/rfc9162'

import cbor from '../cbor'
import { RequestInclusionProofVerification } from '../types'
import attachPayload from '../attachPayload'
import unprotectedHeader from '../unprotectedHeader'

import verifiable_data_structure_proofs from '../verifiable_data_structure_proofs'

export const verify_inclusion_proof = async ({
  leaf,
  signed_inclusion_proof,
  verifier,
}: RequestInclusionProofVerification): Promise<boolean> => {
  const decodedSignedInclusionProof = cbor.web.decode(signed_inclusion_proof)
  const verifiable_proofs = decodedSignedInclusionProof.value[1].get(unprotectedHeader.verifiable_data_structure_proofs)
  const inclusionProofs = verifiable_proofs.get(verifiable_data_structure_proofs.inclusion_proof)
  const [tree_size, leaf_index, inclusion_path] = cbor.web.decode(
    inclusionProofs[0]
  )
  const validated_root = await CoMETRE.RFC9162_SHA256.verify_inclusion_proof(
    leaf,
    {
      log_id: '',
      tree_size,
      leaf_index,
      inclusion_path,
    },
  )
  const attached = await attachPayload({
    signature: signed_inclusion_proof,
    payload: validated_root
  })
  await verifier.verify(attached)
  return true

}
