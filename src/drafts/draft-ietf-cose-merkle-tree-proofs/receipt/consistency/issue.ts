
import { CoMETRE } from '@transmute/rfc9162'

import { cbor, VerifiableDataProofTypes, VerifiableDataStructures } from '../../../..'

import { CoseSign1Bytes, CoseSign1Signer } from "../../../../cose/sign1"
import { toArrayBuffer } from '../../../../cbor'

import { draft_headers } from '../../../..'

import { HeaderMap } from '../../../..'


export type RequestIssueConsistencyReceipt = {
  protectedHeader: HeaderMap
  receipt: CoseSign1Bytes,
  entries: Uint8Array[]
  signer: CoseSign1Signer
}

export const issue = async (req: RequestIssueConsistencyReceipt) => {
  const { protectedHeader, receipt, entries, signer } = req;
  const consistencyVds = protectedHeader.get(draft_headers.verifiable_data_structure)
  if (consistencyVds !== VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }

  const { tag, value } = cbor.decode(receipt);
  if (tag !== 18) {
    throw new Error('Receipt is not tagged cose sign1')
  }

  const [protectedHeaderBytes, unprotectedHeaderMap, payload] = value
  const receiptProtectedHeader = cbor.decode(protectedHeaderBytes)
  const inclusionVds = receiptProtectedHeader.get(draft_headers.verifiable_data_structure);
  if (inclusionVds !== VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }

  const [inclusion] = unprotectedHeaderMap.get(draft_headers.verifiable_data_proofs)
    .get(VerifiableDataProofTypes['RFC9162-Inclusion-Proof']) // get first inclusion proof
  if (payload !== null) {
    throw new Error('payload must be null for this type of proof')
  }
  const [tree_size, leaf_index, inclusion_path] = cbor.decode(inclusion)

  const consistency_proof = await CoMETRE.RFC9162_SHA256.consistency_proof(
    {
      log_id: '',
      tree_size,
      leaf_index,
      inclusion_path,
    },
    entries,
  )

  const root = await CoMETRE.RFC9162_SHA256.root(entries)

  const proofs = new Map();
  proofs.set(VerifiableDataProofTypes['RFC9162-Consistency-Proof'], [ // -2 is consistency proof for 395 (vds), 1 (RFC9162)
    cbor.encode([
      consistency_proof.tree_size_1,
      consistency_proof.tree_size_2,
      consistency_proof.consistency_path.map(toArrayBuffer),
    ]),
  ])

  const unprotectedHeader = new Map();
  unprotectedHeader.set(draft_headers.verifiable_data_proofs, proofs)

  const consistency = new Uint8Array(await signer.sign({
    protectedHeader,
    unprotectedHeader,
    payload: root
  }))

  return { root, receipt: consistency, }
}