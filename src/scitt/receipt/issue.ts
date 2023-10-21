
import merkle from "../../merkle"

import { CoMETRE } from '@transmute/rfc9162'
import unprotectedHeader from '../../unprotectedHeader'
import cbor from '../../cbor'
import detachPayload from '../../detachPayload'
import { typedArrayToBuffer } from '../../utils'

import verifiable_data_structure_proofs from '../../verifiable_data_structure_proofs'

import * as key from '../../key'

import { SecretCoseKeyMap } from '../../key/types'

import getSigner from "../../lib/signer"

export type RequestScittReceipt = {
  index: number
  entries?: ArrayBuffer[]
  leaves?: Uint8Array[]

  signer?: any,
  secretCoseKey?: SecretCoseKeyMap
}

export const issue = async ({ index, entries, leaves, signer, secretCoseKey }: RequestScittReceipt): Promise<ArrayBuffer> => {
  let treeLeaves = leaves
  if (entries) {
    treeLeaves = entries.map((entry: ArrayBuffer) => {
      return merkle.leaf(new Uint8Array(entry))
    })
  }
  if (!treeLeaves?.length) {
    throw new Error('Log must have at least one entry to produce a receipt')
  }
  const root = CoMETRE.RFC9162_SHA256.root(treeLeaves)
  const inclusion_proof = CoMETRE.RFC9162_SHA256.inclusion_proof(
    index,
    treeLeaves
  )
  let receiptSigner = signer
  const protectedHeaderMap = new Map()
  if (secretCoseKey) {
    const secretKeyJwk = await key.exportJWK(secretCoseKey as any)
    secretKeyJwk.alg = key.utils.algorithms.toJOSE.get(secretCoseKey.get(3) as number)
    protectedHeaderMap.set(1, secretCoseKey.get(3) as number) // set alg from the restricted key
    protectedHeaderMap.set(4, secretCoseKey.get(2) as number) // set kid from the restricted key
    protectedHeaderMap.set(unprotectedHeader.verifiable_data_structure, 1) // using RFC9162 verifiable data structure
    receiptSigner = getSigner({
      secretKeyJwk: secretKeyJwk as any
    })
  }


  const unprotectedHeaderMap = new Map()
  const signedMerkleTreeRoot = await receiptSigner.sign({
    protectedHeader: protectedHeaderMap,
    unprotectedHeader: unprotectedHeaderMap,
    payload: typedArrayToBuffer(root) as any
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
  const signedInclusionProof = unprotectedHeader.set(signedMerkleTreeRoot, signedInclusionProofUnprotectedHeader)
  const { signature } = await detachPayload(signedInclusionProof)
  return typedArrayToBuffer(signature)

}