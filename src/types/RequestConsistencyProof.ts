import { CoseSigner } from './CoseSigner'

export type RequestConsistencyProof = {
  kid: string
  alg: string
  signed_inclusion_proof: Uint8Array
  leaves: Uint8Array[]
  signer: CoseSigner
}
