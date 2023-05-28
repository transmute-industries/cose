import { CoMETRE } from '@transmute/rfc9162'

import { sign_root } from './sign_root'
import { sign_inclusion_proof } from './sign_inclusion_proof'
import { verify_inclusion_proof } from './verify_inclusion_proof'
import { sign_consistency_proof } from './sign_consistency_proof'
import { verify_consistency_proof } from './verify_consistency_proof'

const merkle = {
  leaf: CoMETRE.RFC9162_SHA256.leaf,
  root: sign_root,
  inclusion_proof: sign_inclusion_proof,
  verify_inclusion_proof: verify_inclusion_proof,
  consistency_proof: sign_consistency_proof,
  verify_consistency_proof: verify_consistency_proof,
}

export default merkle
