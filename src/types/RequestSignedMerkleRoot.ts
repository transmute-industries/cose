import { CoseSigner } from './CoseSigner'
export type RequestSignedMerkleRoot = {
  alg: string
  kid: string
  leaves: Uint8Array[]
  signer?: CoseSigner
}
