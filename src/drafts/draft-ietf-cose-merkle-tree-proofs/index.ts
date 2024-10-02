
export * from './encode_inclusion_proof'
export * from './decode_inclusion_proof'

export * from './encode_consistency_proof'
export * from './decode_consistency_proof'

export * from './add_receipt'

export const verifiable_data_structures = {
  rfc9162_sha256: 1
}

export const transparency = new Map([
  [1, 'RFC9162 SHA-256'],
  [-1, 'inclusion'],
  [-2, 'consistency']
])

export const rfc9162_sha256_proof_types = {
  'inclusion': -1,
  'consistency': -2
}

export * from './log'