
import subtle from "./subtle";

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

