
import { exportJWK, KeyLike, JWK, generateKeyPair, calculateJwkThumbprint } from 'jose'

import { web_key_type, private_rsa_web_key_params, private_oct_web_key_params, private_ec_web_key_params, private_okp_web_key_params, jose_key_type } from '../iana/assignments/jose'

type signature_algorithms = 'ES256'

type algorithm_specified_key_params = {
  'ES256': {
    kty: 'EC'
    crv: 'P-256'
    alg: 'ES256',
    x: string
    y: string
    d?: string
  }
}

export type fully_specified_web_key<T extends signature_algorithms> = web_key_type & algorithm_specified_key_params[T]

export const format_web_key = (jwk: JWK) => {
  const { kid, alg, kty, crv, x, y, d, ext, ...rest } = jwk
  return JSON.parse(JSON.stringify({
    kid, alg, kty, crv, x, y, d, ext, ...rest
  }))
}

const without_private_information = <T>(jwk: JWK, private_params: Record<string, string>) => {
  const public_information = {} as Record<string, unknown>
  for (const [key, value] of Object.entries(jwk)) {
    if (key in private_params) {
      continue
    }
    public_information[key] = value
  }
  return format_web_key(public_information) as T
}

export const export_public_web_key_with_algorithm = async <T extends signature_algorithms>(k: KeyLike, alg: signature_algorithms, ext: boolean, kid?: string): Promise<fully_specified_web_key<T>> => {
  const jwk = await exportJWK(k);
  jwk.alg = alg
  jwk.ext = ext
  jwk.kid = kid || await calculateJwkThumbprint(jwk)
  const { kty } = jwk
  switch (kty) {
    case jose_key_type.RSA: {
      return without_private_information(jwk, private_rsa_web_key_params)
    }
    case jose_key_type.EC: {
      return without_private_information(jwk, private_ec_web_key_params)
    }
    case jose_key_type.OKP: {
      return without_private_information(jwk, private_okp_web_key_params)
    }
    case jose_key_type.oct: {
      return without_private_information(jwk, private_oct_web_key_params)
    }
    default: {
      throw new Error('Unknown key type: ' + kty)
    }
  }
}

export const export_private_web_key_with_algorithm = async <T extends signature_algorithms>(k: KeyLike, alg: signature_algorithms): Promise<fully_specified_web_key<T>> => {
  const privateKey = await exportJWK(k);
  privateKey.alg = alg
  privateKey.ext = true; // impossible to export otherwise.
  privateKey.kid = await calculateJwkThumbprint(privateKey)
  return format_web_key(privateKey) as fully_specified_web_key<T>
}

export type RequestFullySpecifiedWebKey = {
  alg: signature_algorithms,
  ext: boolean,
  kid?: string
}
export const generate_web_key = async ({ alg, ext, kid }: RequestFullySpecifiedWebKey) => {
  const k = await generateKeyPair(alg, { extractable: ext })
  return {
    publicKey: await export_public_web_key_with_algorithm(k.publicKey, alg, ext, kid),
    privateKey: await export_private_web_key_with_algorithm(k.privateKey, alg),
  }
}
