import { RFC9162, CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestConsistencyProof } from '../types'

const { tree_alg } = CoMETRE.RFC9162_SHA256
export const sign_consistency_proof = async ({
  log_id,
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
  const prefix = `urn:ietf:params:trans:consistency`
  const leaf = leaves[leaf_index]
  const new_root = CoMETRE.RFC9162_SHA256.root(leaves)
  const signed_root = await signer.sign({
    protectedHeader: {
      alg: signer.alg,
      kid:
        log_id +
        '/' +
        `${prefix}:${tree_alg.toLowerCase()}:${RFC9162.binToHex(leaf)}`,
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
