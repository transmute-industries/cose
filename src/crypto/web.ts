
import subtle from "./subtle";
import { any_cose_key, cose_key, cose_key_type } from "../iana/assignments/cose"
import { cose_key_to_web_key } from "./key"

export const webCryptoKeyParamsByCoseAlgorithm = {
  'ESP256': {
    name: "ECDSA",
    hash: 'SHA-256',
    namedCurve: 'P-256', // true
  },
  'ES256': {
    name: "ECDSA",
    hash: 'SHA-256',
    namedCurve: 'P-256', // not true...
  },
  'ES384': {
    name: "ECDSA",
    hash: 'SHA-384',
    namedCurve: 'P-384', // not true...
  },
  'ES521': {
    name: "ECDSA",
    hash: 'SHA-512',
    namedCurve: 'P-521', // not true...
  }
} as const

export type WebCryptoCoseAlgorithm = keyof typeof webCryptoKeyParamsByCoseAlgorithm

export const signer = ({ key, algorithm }: { key: CryptoKey, algorithm: WebCryptoCoseAlgorithm }) => {
  return {
    sign: async (toBeSigned: Uint8Array): Promise<Uint8Array> => {
      return subtle().then(async (subtle) => {
        return new Uint8Array(await subtle.sign(
          webCryptoKeyParamsByCoseAlgorithm[algorithm],
          key,
          toBeSigned,
        ))
      })
    }
  }
}

export const verifier = ({ key, algorithm }: { key: CryptoKey, algorithm: WebCryptoCoseAlgorithm }) => {
  return {
    verify: async (toBeSigned: ArrayBuffer, signature: ArrayBuffer): Promise<ArrayBuffer> => {
      return subtle().then(async (subtle) => {
        const verified = await subtle.verify(
          webCryptoKeyParamsByCoseAlgorithm[algorithm],
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


export const web_key_to_crypto_key = async (jwk: any, key_ops?: string[]): Promise<CryptoKey> => {
  if (jwk.kty != 'EC') {
    throw new Error('Only EC keys are supported')
  }
  return subtle().then((subtle) => {
    const { alg, ...unrestrictedKey } = jwk
    if (!webCryptoKeyParamsByCoseAlgorithm[alg as WebCryptoCoseAlgorithm]) {
      throw new Error('Unknown algorithm: ' + alg)
    }
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