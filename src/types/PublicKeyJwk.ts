export type PublicKeyJwk = {
  kty: 'EC' | 'OKP'
  crv: 'P-256' | 'P-384' | 'P-521' | 'Ed25519' | 'secp256k1'
  alg: 'ES256' | 'ES384' | 'ES512' | 'EdDSA' | 'ES256K' | string
  x: string
  y: string
}
