
import { CoMETRE } from '@transmute/rfc9162'

import { cbor } from '../../..'

import { CoseSign1Bytes, CoseSign1DetachedVerifier } from "../../sign1"

export type RequestVerifyConsistencyReceipt = {
  oldRoot: ArrayBuffer,
  newRoot: ArrayBuffer,
  receipt: CoseSign1Bytes,
  verifier: CoseSign1DetachedVerifier
}

export const verify = async (req: RequestVerifyConsistencyReceipt) => {
  const { newRoot, oldRoot, receipt, verifier } = req
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
  const [consistency] = proofs.get(-2) // get first consistency proof
  if (payload !== null) {
    throw new Error('payload must be null for this type of proof')
  }
  const [tree_size_1,
    tree_size_2,
    consistency_path] = cbor.decode(consistency)

  const verifiedNewRoot = await verifier.verify({ coseSign1: receipt, payload: newRoot })
  const verified = await CoMETRE.RFC9162_SHA256.verify_consistency_proof(
    new Uint8Array(oldRoot),
    new Uint8Array(verifiedNewRoot),
    {
      log_id: '',
      tree_size_1,
      tree_size_2,
      consistency_path,
    },
  )
  return verified

}