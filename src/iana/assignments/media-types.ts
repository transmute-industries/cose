export type application_cose = 'application/cose'
export type application_cose_key = 'application/cose-key'
export type application_jwk = 'application/jwk+json'

export type crypto_key_type = application_cose_key | application_jwk

export type diagnostic_types = application_cose | application_cose_key