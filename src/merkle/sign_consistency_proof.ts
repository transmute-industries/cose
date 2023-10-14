import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestConsistencyProof } from '../types'

export const sign_consistency_proof = async ({
  kid,
  alg,
  leaves,
  signed_inclusion_proof,
  signer,
}: RequestConsistencyProof) => {
  const decoded = cbor.web.decode(signed_inclusion_proof)
  const [tree_size, leaf_index, inclusion_path] = cbor.web.decode(
    decoded.value[1].get(100),
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
      kid
    },
    payload: new_root,
  })
  const signedConsistencyProofUnprotectedHeader = new Map()
  signedConsistencyProofUnprotectedHeader.set(
    unprotectedHeader.consistency_proof,
    cbor.web.encode([
      consistency_proof.tree_size_1,
      consistency_proof.tree_size_2,
      consistency_proof.consistency_path,
    ]),
  )
  const signedConsistencyProof = unprotectedHeader.set(signedMerkleRoot, signedConsistencyProofUnprotectedHeader)
  return signedConsistencyProof
}
