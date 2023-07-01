import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../unprotectedHeader'
import cbor from '../cbor'
import { RequestInclusionProof } from '../types'
import detachPayload from '../detachPayload'
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
  const signed_root = await signer.sign({
    protectedHeader: {
      alg,
      kid,
    },
    payload: root,
  })
  const u = new Map()
  u.set(
    unprotectedHeader.inclusion_proof,
    cbor.encode([
      inclusion_proof.tree_size,
      inclusion_proof.leaf_index,
      inclusion_proof.inclusion_path,
    ]),
  )
  const updated = unprotectedHeader.set(signed_root, u)
  const { signature } = await detachPayload(updated)
  return signature
}
