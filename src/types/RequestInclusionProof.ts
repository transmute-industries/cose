import { CoseSigner } from './CoseSigner'

export type RequestInclusionProof = {
  leaf_index: number
  leaves: Uint8Array[]
  signer: CoseSigner
}
