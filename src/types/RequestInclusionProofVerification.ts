import { CoseVerifier } from './CoseVerifier'

export type RequestInclusionProofVerification = {
  leaf: Uint8Array
  signed_inclusion_proof: Uint8Array
  verifier: CoseVerifier
}
