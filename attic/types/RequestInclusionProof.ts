import { CoseSigner } from './CoseSigner'

export type RequestInclusionProof = {
  kid: string
  alg: string
  leaf_index: number
  leaves: Uint8Array[]
  signer: CoseSigner
}
