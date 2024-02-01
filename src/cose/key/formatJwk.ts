

export const formatJwk = (jwk: any) => {
  const { kid, alg, kty, crv, x, y, d, ...rest } = jwk
  return JSON.parse(JSON.stringify({ kid, alg, kty, crv, x, y, d, ...rest })) as any
}