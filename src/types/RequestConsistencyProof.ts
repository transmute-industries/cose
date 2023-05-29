import { CoseSigner } from './CoseSigner'

export type RequestConsistencyProof = {
  log_id: string
  signed_inclusion_proof: Uint8Array
  leaves: Uint8Array[]
  signer: CoseSigner
}
