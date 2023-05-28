import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestInclusionProof } from '../types'
import detachPayload from '../detachPayload'
export const sign_inclusion_proof = async ({
  leaf_index,
  leaves,
  signer,
}: RequestInclusionProof) => {
  const root = CoMETRE.RFC9162_SHA256.root(leaves)
  const inclusion_proof = CoMETRE.RFC9162_SHA256.inclusion_proof(
    leaf_index,
    leaves,
  )
  const signed_root = await signer.sign({
    protectedHeader: {
      alg: signer.alg,
    },
    payload: root,
  })
  const u = new Map()
  u.set(
    unprotectedHeader.inclusion_proof,
    cbor.encode([
      inclusion_proof.log_id,
      inclusion_proof.tree_size,
      inclusion_proof.leaf_index,
      inclusion_proof.inclusion_path,
    ]),
  )
  const updated = unprotectedHeader.set(signed_root, u)
  const { signed } = detachPayload(updated)
  return new Uint8Array(signed)
}
