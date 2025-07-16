export * from './types'
export * from './ccf_leaf'
export * from './ccf_proof'
export * from './ccf_verifier'

export const ccf_verifiable_data_structures = {
    ccf_ledger_sha256: 2
}

export const ccf_proof_types = {
    'inclusion': -1
}

export const ccf_transparency = new Map([
    [2, 'CCF Ledger SHA-256'],
    [-1, 'inclusion']
]) 