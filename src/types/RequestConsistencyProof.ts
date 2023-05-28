import { CoseSigner } from './CoseSigner'

export type RequestConsistencyProof = {
  signed_inclusion_proof: Uint8Array
  leaves: Uint8Array[]
  signer: CoseSigner
}
