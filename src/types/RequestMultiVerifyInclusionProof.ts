import { CoseVerifier } from './CoseVerifier'

export type RequestMultiVerifyInclusionProof = {
  leaves: Uint8Array[]
  signed_inclusion_proof: Uint8Array
  verifier: CoseVerifier
}
