import { CoMETRE } from '@transmute/rfc9162'

import cbor from '../cbor'
import { RequestInclusionProofVerification } from '../types'
import attachPayload from '../attachPayload'
export const verify_inclusion_proof = async ({
  leaf,
  signed_inclusion_proof,
  verifier,
}: RequestInclusionProofVerification): Promise<boolean> => {
  const decoded = cbor.web.decode(signed_inclusion_proof)
  const proofs = cbor.web.decode(
    decoded.value[1].get(100),
  )
  const [tree_size, leaf_index, inclusion_path] = cbor.web.decode(
    proofs[0]
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
