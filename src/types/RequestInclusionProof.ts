import { CoseSigner } from './CoseSigner'

export type RequestInclusionProof = {
  log_id: string
  leaf_index: number
  leaves: Uint8Array[]
  signer: CoseSigner
}
