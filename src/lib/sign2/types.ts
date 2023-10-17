export type PublicKeyJwk = {
  alg: string
  kty: string
  crv: string
  x: string
  y: string
}

export type SecretKeyJwk = PublicKeyJwk & {
  d: string
}