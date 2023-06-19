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
  const decoded = cbor.decode(signed_inclusion_proof)
  const [tree_size, leaf_index, inclusion_path] = cbor.decode(
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
  const signed_root = await signer.sign({
    protectedHeader: {
      alg,
      kid
    },
    payload: new_root,
  })
  const u = new Map()
  u.set(
    unprotectedHeader.consistency_proof,
    cbor.encode([
      consistency_proof.tree_size_1,
      consistency_proof.tree_size_2,
      consistency_proof.consistency_path,
    ]),
  )
  const updated = unprotectedHeader.set(signed_root, u)
  return updated
}
