import subtle from "./subtle"

const webCryptoKeyParamsByCoseAlgorithm = {
  'ES256': {
    name: "ECDSA",
    namedCurve: 'P-256', // not true...
  },
  'ES384': {
    name: "ECDSA",
    namedCurve: 'P-384', // not true...
  },
  'ES521': {
    name: "ECDSA",
    namedCurve: 'P-521', // not true...
  }
} as const

export type WebCryptoCoseAlgorithm = keyof typeof webCryptoKeyParamsByCoseAlgorithm

export const web_key_to_crypto_key = async (jwk: any, key_ops?: string[]): Promise<CryptoKey> => {
  if (jwk.kty != 'EC') {
    throw new Error('Only EC keys are supported')
  }
  return subtle().then((subtle) => {
    const { alg, ...unrestrictedKey } = jwk
    return subtle.importKey(
      "jwk",
      unrestrictedKey,
      webCryptoKeyParamsByCoseAlgorithm[alg as WebCryptoCoseAlgorithm],
      jwk.ext || true,
      jwk.key_ops || key_ops || [],
    )
  })
}