import { JWK } from "jose"

export const formatJwk = (jwk: JWK) => {
  const { kid, alg, kty, crv, x, y, d, ...rest } = jwk
  return JSON.parse(JSON.stringify({ kid, alg, kty, crv, x, y, d, ...rest })) as JWK
}