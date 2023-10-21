import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestInclusionProof } from '../types'
import detachPayload from '../detachPayload'
import { typedArrayToBuffer } from '../utils'

import verifiable_data_structure_proofs from '../verifiable_data_structure_proofs'

export const sign_inclusion_proof = async ({
  kid,
  alg,
  leaf_index,
  leaves,
  signer,
}: RequestInclusionProof) => {
  const root = CoMETRE.RFC9162_SHA256.root(leaves)
  const inclusion_proof = CoMETRE.RFC9162_SHA256.inclusion_proof(
    leaf_index,
    leaves,
  )
  const signedMerkleRoot = await signer.sign({
    protectedHeader: {
      alg,
      kid,
      verifiable_data_structure: 'RFC9162_SHA256'
    },
    payload: root,
  })
  const signedInclusionProofUnprotectedHeader = new Map()
  const verifiable_proofs = new Map();
  verifiable_proofs.set(verifiable_data_structure_proofs.inclusion_proof, [
    cbor.web.encode([
      inclusion_proof.tree_size,
      inclusion_proof.leaf_index,
      inclusion_proof.inclusion_path.map(typedArrayToBuffer),
    ])
  ])
  signedInclusionProofUnprotectedHeader.set(
    unprotectedHeader.verifiable_data_structure_proofs,
    verifiable_proofs
  )
  const signedInclusionProof = unprotectedHeader.set(signedMerkleRoot, signedInclusionProofUnprotectedHeader)
  // TODO: remove this and require a detached signer?
  const { signature } = await detachPayload(signedInclusionProof)
  return signature
}
