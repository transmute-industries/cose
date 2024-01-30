
import { CoMETRE } from '@transmute/rfc9162'

import { cbor } from '../../..'

import { CoseSign1Bytes, CoseSign1Signer, ProtectedHeaderMap } from "../../sign1"
import { toArrayBuffer } from '../../../cbor'

export type RequestIssueConsistencyReceipt = {
  protectedHeader: ProtectedHeaderMap
  receipt: CoseSign1Bytes,
  entries: Uint8Array[]
  signer: CoseSign1Signer
}

export const issue = async (req: RequestIssueConsistencyReceipt) => {
  const { protectedHeader, receipt, entries, signer } = req;
  const consistencyVds = protectedHeader.get(-111)
  if (consistencyVds !== 1) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }

  const { tag, value } = cbor.decode(receipt);
  if (tag !== 18) {
    throw new Error('Receipt is not tagged cose sign1')
  }

  const [protectedHeaderBytes, unprotectedHeaderMap, payload] = value
  const receiptProtectedHeader = cbor.decode(protectedHeaderBytes)
  const inclusionVds = receiptProtectedHeader.get(-111);
  if (inclusionVds !== 1) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }

  const [inclusion] = unprotectedHeaderMap.get(-222).get(-1) // get first inclusion proof
  if (payload !== undefined) {
    throw new Error('payload must be undefined for this type of proof')
  }
  const [tree_size, leaf_index, inclusion_path] = cbor.decode(inclusion)

  const consistency_proof = CoMETRE.RFC9162_SHA256.consistency_proof(
    {
      log_id: '',
      tree_size,
      leaf_index,
      inclusion_path,
    },
    entries,
  )

  const root = CoMETRE.RFC9162_SHA256.root(entries)

  const proofs = new Map();
  proofs.set(-2, [ // -2 is consistency proof for -111 (vds), 1 (RFC9162)
    cbor.encode([
      consistency_proof.tree_size_1,
      consistency_proof.tree_size_2,
      consistency_proof.consistency_path.map(toArrayBuffer),
    ]),
  ])

  const unprotectedHeader = new Map();
  unprotectedHeader.set(-222, proofs)

  const consistency = await signer.sign({
    protectedHeader,
    unprotectedHeader,
    payload: root
  })

  return { root, receipt: consistency, }
}