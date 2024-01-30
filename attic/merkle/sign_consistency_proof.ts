import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestConsistencyProof } from '../types'
import { typedArrayToBuffer } from '../utils'

import verifiable_data_structure_proofs from '../verifiable_data_structure_proofs'

export const sign_consistency_proof = async ({
  kid,
  alg,
  leaves,
  signed_inclusion_proof,
  signer,
}: RequestConsistencyProof) => {
  const decodedSignedInclusionProof = cbor.web.decode(signed_inclusion_proof)
  const inclusionProofs = decodedSignedInclusionProof.value[1].get(unprotectedHeader.verifiable_data_structure_proofs)
  const proofs = inclusionProofs.get(verifiable_data_structure_proofs.inclusion_proof)
  const [tree_size, leaf_index, inclusion_path] = cbor.web.decode(
    proofs[0] // expect never more than 1 consistency proof?
  )
  const consistency_proof = CoMETRE.RFC9162_SHA256.consistency_proof(
    {
      log_id: '',
      tree_size,
      leaf_index,
      inclusion_path,
    },
    leaves,
  )
  const new_root = CoMETRE.RFC9162_SHA256.root(leaves)
  const signedMerkleRoot = await signer.sign({
    protectedHeader: {
      alg,
      kid,
      verifiable_data_structure: 'RFC9162_SHA256'
    },
    payload: new_root,
  })
  const signedConsistencyProofUnprotectedHeader = new Map()
  const consistencyProofs = new Map();
  consistencyProofs.set(verifiable_data_structure_proofs.consistency_proof, [
    cbor.web.encode([
      consistency_proof.tree_size_1,
      consistency_proof.tree_size_2,
      consistency_proof.consistency_path.map(typedArrayToBuffer),
    ]),
  ])
  signedConsistencyProofUnprotectedHeader.set(
    unprotectedHeader.verifiable_data_structure_proofs,
    consistencyProofs
  )
  const signedConsistencyProof = unprotectedHeader.set(signedMerkleRoot, signedConsistencyProofUnprotectedHeader)
  return signedConsistencyProof
}
