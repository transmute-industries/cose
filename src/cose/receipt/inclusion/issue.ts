
import { CoMETRE } from '@transmute/rfc9162'

import { cbor } from '../../..'

import { CoseSign1Signer, ProtectedHeaderMap } from "../../sign1"

export type RequestIssueInclusionReceipt = {
  protectedHeader: ProtectedHeaderMap
  entry: number,
  entries: Uint8Array[]
  signer: CoseSign1Signer
}

export const issue = async (req: RequestIssueInclusionReceipt) => {
  const { protectedHeader, entry, entries, signer } = req;
  const vds = protectedHeader.get(395)
  if (vds !== 1) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }
  const root = await CoMETRE.RFC9162_SHA256.root(entries)
  const proof = await CoMETRE.RFC9162_SHA256.inclusion_proof(
    entry,
    entries,
  )
  const proofs = new Map();
  proofs.set(-1, [ // -1 is inclusion proof for 395 (vds), 1 (RFC9162)
    cbor.encode([ // encoded proof
      proof.tree_size,
      proof.leaf_index,
      proof.inclusion_path.map(cbor.toArrayBuffer),
    ])
  ])
  const unprotectedHeader = new Map();
  unprotectedHeader.set(396, proofs)
  return signer.sign({
    protectedHeader,
    unprotectedHeader,
    payload: root
  })
}