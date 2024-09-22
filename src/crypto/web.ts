
import subtle from "./subtle";
import { any_cose_key, cose_key, cose_key_type } from "../iana/assignments/cose"
import { cose_key_to_web_key } from "./key"


export const webCryptoSignatureAlgorithmByCoseSignatureAlgorithm = {
  'ES256': {
    name: "ECDSA",
    hash: { name: 'SHA-256' },
  },
  'ES384': {
    name: "ECDSA",
    hash: { name: 'SHA-384' },
  },
  'ES521': {
    name: "ECDSA",
    hash: { name: 'SHA-512' },
  }
} as const

export type WebCryptoCoseSignatureAlgorithm = keyof typeof webCryptoSignatureAlgorithmByCoseSignatureAlgorithm

export const signer = ({ key, algorithm }: { key: CryptoKey, algorithm: WebCryptoCoseSignatureAlgorithm }) => {
  return {
    sign: async (toBeSigned: ArrayBuffer): Promise<ArrayBuffer> => {
      return subtle().then((subtle) => {
        return subtle.sign(
          webCryptoSignatureAlgorithmByCoseSignatureAlgorithm[algorithm],
          key,
          toBeSigned,
        )
      })
    }
  }
}

export const verifier = ({ key, algorithm }: { key: CryptoKey, algorithm: WebCryptoCoseSignatureAlgorithm }) => {
  return {
    verify: async (toBeSigned: ArrayBuffer, signature: ArrayBuffer): Promise<ArrayBuffer> => {
      return subtle().then(async (subtle) => {
        const verified = await subtle.verify(
          webCryptoSignatureAlgorithmByCoseSignatureAlgorithm[algorithm],
          key,
          signature,
          toBeSigned,
        );
        if (!verified) {
          throw new Error('Signature verification failed');
        }
        return toBeSigned;
      })
    }
  }
}

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

export const cose_key_to_crypto_key = async (key: any_cose_key): Promise<CryptoKey> => {
  if (key.get(cose_key.kty) != cose_key_type.ec2) {
    throw new Error('Only EC2 keys are supported')
  }
  const jwk = await cose_key_to_web_key<any>(key)
  return web_key_to_crypto_key(jwk)
}