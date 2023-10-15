
import cbor from '../cbor'
import { RequestMultiVerifyInclusionProof } from '../types'
import { verify_inclusion_proof } from './verify_inclusion_proof'
import unprotectedHeader from '../unprotectedHeader'
export const verify_multiple = async ({
  leaves,
  signed_inclusion_proof,
  verifier,
}: RequestMultiVerifyInclusionProof) => {
  const decoded = cbor.web.decode(signed_inclusion_proof)
  const proofs = cbor.web.decode(
    decoded.value[1].get(100),
  )
  const verifications = [] as boolean[]
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i]
    const proof = proofs[i]
    const updateHeader = unprotectedHeader.get(signed_inclusion_proof)
    updateHeader.set(100, cbor.web.encode([proof]))
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
