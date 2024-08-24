
import { CoMETRE } from '@transmute/rfc9162'

import { cbor, Protected, Unprotected, VerifiableDataProofTypes, VerifiableDataStructures } from '../../..'

import { CoseSign1Signer, ProtectedHeaderMap } from "../../sign1"

export type RequestIssueInclusionReceipt = {
  protectedHeader: ProtectedHeaderMap
  entry: number,
  entries: Uint8Array[]
  signer: CoseSign1Signer
}

export const issue = async (req: RequestIssueInclusionReceipt) => {
  const { protectedHeader, entry, entries, signer } = req;
  const vds = protectedHeader.get(Protected.VerifiableDataStructure)
  if (vds !== VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }
  const root = await CoMETRE.RFC9162_SHA256.root(entries)
  const proof = await CoMETRE.RFC9162_SHA256.inclusion_proof(
    entry,
    entries,
  )
  const proofs = new Map();
  proofs.set(VerifiableDataProofTypes['RFC9162-Inclusion-Proof'], [ // -1 is inclusion proof for 395 (vds), 1 (RFC9162)
    cbor.encode([ // encoded proof
      proof.tree_size,
      proof.leaf_index,
      proof.inclusion_path.map(cbor.toArrayBuffer),
    ])
  ])
  const unprotectedHeader = new Map();
  unprotectedHeader.set(Unprotected.VerifiableDataProofs, proofs)
  return signer.sign({
    protectedHeader,
    unprotectedHeader,
    payload: root
  })
}