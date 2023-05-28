import { CoseVerifier } from './CoseVerifier'

export type RequestConsistencyProofVerification = {
  old_root: Uint8Array
  signed_consistency_proof: Uint8Array
  verifier: CoseVerifier
}
