import { CoseSigner } from './CoseSigner'
export type RequestSignedMerkleRoot = {
  leaves: Uint8Array[]
  signer?: CoseSigner
}
