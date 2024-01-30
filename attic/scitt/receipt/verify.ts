
import merkle from "../../merkle"

import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../../unprotectedHeader'
import cbor from '../../cbor'
import attachPayload from '../../attachPayload'

import verifiable_data_structure_proofs from '../../verifiable_data_structure_proofs'

import * as key from '../../key'

import { PublicCoseKeyMap } from '../../key/types'

import getVerifier from "../../lib/verifier"

export type RequestScittReceiptVerify = {
  receipt: ArrayBuffer

  publicCoseKey?: PublicCoseKeyMap
  verifier?: any

  entry?: ArrayBuffer
  leaf?: Uint8Array
}

export const verify = async ({ entry, leaf, receipt, verifier, publicCoseKey }: RequestScittReceiptVerify): Promise<boolean> => {
  try {
    let receiptVerifier = verifier
    if (publicCoseKey) {
      const publicKeyJwk = await key.exportJWK(publicCoseKey as any)
      publicKeyJwk.alg = key.utils.algorithms.toJOSE.get(publicCoseKey.get(3) as number)
      receiptVerifier = getVerifier({
        publicKeyJwk: publicKeyJwk as any
      })
    }
    let treeLeaf = leaf
    if (entry) {
      treeLeaf = merkle.leaf(new Uint8Array(entry))
    }
    if (!treeLeaf) {
      throw new Error('A leaf or entry is required to verify a receipt.')
    }
    const decodedSignedInclusionProof = cbor.web.decode(receipt)
    const verifiable_proofs = decodedSignedInclusionProof.value[1].get(unprotectedHeader.verifiable_data_structure_proofs)
    const inclusionProofs = verifiable_proofs.get(verifiable_data_structure_proofs.inclusion_proof)
    const [tree_size, leaf_index, inclusion_path] = cbor.web.decode(
      inclusionProofs[0]
    )
    const validated_root = await CoMETRE.RFC9162_SHA256.verify_inclusion_proof(
      treeLeaf,
      {
        log_id: '',
        tree_size,
        leaf_index,
        inclusion_path,
      },
    )
    const attached = await attachPayload({
      signature: new Uint8Array(receipt),
      payload: validated_root
    })
    receiptVerifier.verify(attached)
    return true
  } catch (e) {
    return false
  }

}