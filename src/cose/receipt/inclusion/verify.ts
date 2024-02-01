
import { CoMETRE } from '@transmute/rfc9162'

import { cbor } from '../../..'

import { CoseSign1Bytes, CoseSign1DetachedVerifier } from "../../sign1"

export type RequestVerifyInclusionReceipt = {
  entry: Uint8Array,
  receipt: CoseSign1Bytes,
  verifier: CoseSign1DetachedVerifier
}

export const verify = async (req: RequestVerifyInclusionReceipt) => {
  const { entry, receipt, verifier } = req
  const { tag, value } = cbor.decode(receipt);
  if (tag !== 18) {
    throw new Error('Receipt is not tagged cose sign1')
  }
  const [protectedHeaderBytes, unprotectedHeaderMap, payload] = value
  const protectedHeader = cbor.decode(protectedHeaderBytes)
  const vds = protectedHeader.get(-111);
  if (vds !== 1) {
    throw new Error('Unsupported verifiable data structure. See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs')
  }
  const proofs = unprotectedHeaderMap.get(-222)
  const [inclusion] = proofs.get(-1) // get first inclusion proof
  if (payload !== null) {
    throw new Error('payload must be null for this type of proof')
  }
  const [tree_size, leaf_index, inclusion_path] = cbor.decode(inclusion)
  const root = await CoMETRE.RFC9162_SHA256.verify_inclusion_proof(
    entry,
    {
      log_id: '',
      tree_size,
      leaf_index,
      inclusion_path,
    },
  )
  const verified = verifier.verify({
    coseSign1: receipt,
    payload: root
  })
  return verified
}