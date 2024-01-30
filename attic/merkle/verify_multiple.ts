
import cbor from '../cbor'
import { RequestMultiVerifyInclusionProof } from '../types'
import { verify_inclusion_proof } from './verify_inclusion_proof'
import unprotectedHeader from '../unprotectedHeader'
import verifiable_data_structure_proofs from '../verifiable_data_structure_proofs'
export const verify_multiple = async ({
  leaves,
  signed_inclusion_proof,
  verifier,
}: RequestMultiVerifyInclusionProof) => {
  const decodedSignedInclusionProof = cbor.web.decode(signed_inclusion_proof)
  const verifiableProofs = decodedSignedInclusionProof.value[1].get(unprotectedHeader.verifiable_data_structure_proofs)
  const proofs = verifiableProofs.get(verifiable_data_structure_proofs.inclusion_proof)
  const verifications = [] as boolean[]
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i]
    const proof = proofs[i]
    const updateHeader = unprotectedHeader.get(signed_inclusion_proof)
    const revisedProofs = new Map();
    revisedProofs.set(verifiable_data_structure_proofs.inclusion_proof, [proof])
    updateHeader.set(unprotectedHeader.verifiable_data_structure_proofs, revisedProofs)
    const updated = unprotectedHeader.set(signed_inclusion_proof, updateHeader)
    const verified = await verify_inclusion_proof({
      leaf,
      signed_inclusion_proof: updated,
      verifier
    })
    verifications.push(verified)
  }

  return verifications.every((v: boolean) => v) // all proofs must verify
}
