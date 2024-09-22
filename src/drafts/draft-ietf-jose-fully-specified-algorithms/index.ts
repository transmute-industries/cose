
import { exportJWK, KeyLike, JWK, generateKeyPair } from 'jose'
import { crypto_key_type } from '../../iana/assignments/media-types'
import { web_key_type, } from '../../iana/assignments/jose'
import { ec2_curves, ec2_key, okp_key, okp_curves } from '../../iana/assignments/cose'

import * as cbor from 'cbor-web'
import { less_specified } from '../../iana/requested/cose'

import { web_key_to_cose_key } from './web_key_to_cose_key'
import { cose_key_to_web_key } from './cose_key_to_web_key'
import { public_from_private } from './public_from_private'
import { web_key_thumbprint } from './thumbprint'

export { web_key_to_cose_key, cose_key_to_web_key, public_from_private }

export * from './thumbprint'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export type algorithm_specified_web_key_params = {
  'ESP256': web_key_type & {
    kty: 'EC'
    crv: 'P-256'
    alg: 'ES256',
    x: string
    y: string
    d?: string
  },
  'ES256': web_key_type & {
    kty: 'EC'
    crv: 'P-256'
    alg: 'ES256',
    x: string
    y: string
    d?: string
  },
  'ES384': web_key_type & {
    kty: 'EC'
    crv: 'P-384'
    alg: 'ES384',
    x: string
    y: string
    d?: string
  },
  'ESP384': web_key_type & {
    kty: 'EC'
    crv: 'P-384'
    alg: 'ES384',
    x: string
    y: string
    d?: string
  },
  'EdDSA': web_key_type & {
    kty: 'OKP'
    crv: 'Ed25519' | 'Ed448'
    alg: 'EdDSA',
    x: string
    d?: string
  },
  'Ed25519': web_key_type & {
    kty: 'OKP'
    crv: 'Ed25519'
    alg: 'Ed25519',
    x: string
    d?: string
  },
  'Ed448': web_key_type & {
    kty: 'OKP'
    crv: 'Ed448'
    alg: 'Ed448',
    x: string
    d?: string
  }
}

export type algorithm_specified_cose_key_params = {
  'ES256': ec2_key & { get(k: -1): ec2_curves.p_256 | ec2_curves.p_384 | ec2_curves.p_521 }
  'ESP256': ec2_key & { get(k: -1): ec2_curves.p_256 }

  'ES384': ec2_key & { get(k: -1): ec2_curves.p_256 | ec2_curves.p_384 | ec2_curves.p_521 }
  'ESP384': ec2_key & { get(k: -1): ec2_curves.p_384 }

  'EdDSA': okp_key & { get(k: -1): okp_curves.ed25519 | okp_curves.ed448 }

  'Ed25519': ec2_key & { get(k: -1): okp_curves.ed25519 }
  'Ed448': ec2_key & { get(k: -1): okp_curves.ed448 }
}

export type fully_specified_signature_algorithms = keyof algorithm_specified_web_key_params
export type fully_specified_web_key<T extends fully_specified_signature_algorithms> = web_key_type & algorithm_specified_web_key_params[T]

export type fully_specified_cose_signature_algorithms = keyof algorithm_specified_cose_key_params
export type fully_specified_cose_key<T extends fully_specified_cose_signature_algorithms> = algorithm_specified_cose_key_params[T]

export type parseable_fully_specified_signature_algorithms = keyof algorithm_specified_cose_key_params | keyof algorithm_specified_web_key_params
export type parsable_fully_specified_keys<alg extends parseable_fully_specified_signature_algorithms, cty extends crypto_key_type> =
  cty extends 'application/jwk+json' ? fully_specified_web_key<alg> : cty extends 'application/cose-key' ? fully_specified_cose_key<alg> : unknown

export type request_crypto_key = {

  type: crypto_key_type,
  algorithm: fully_specified_signature_algorithms

  id?: string,
  extractable?: boolean
}


export const format_web_key = (jwk: JWK) => {
  const { kid, alg, kty, crv, x, y, d, ext, ...rest } = jwk
  return JSON.parse(JSON.stringify({
    kid, alg, kty, crv, x, y, d, ext, ...rest
  }))
}

export const without_private_information = <T>(jwk: JWK, private_params: Record<string, string>) => {
  const public_information = {} as Record<string, unknown>
  for (const [key, value] of Object.entries(jwk)) {
    if (key in private_params) {
      continue
    }
    public_information[key] = value
  }
  return format_web_key(public_information) as T
}

export const export_public_web_key_with_algorithm = async <alg extends parseable_fully_specified_signature_algorithms>(
  k: KeyLike,
  alg: alg,
  ext: boolean,
  kid?: string
): Promise<fully_specified_web_key<alg>> => {
  const jwk = await exportJWK(k);
  jwk.alg = alg
  jwk.ext = ext
  jwk.kid = kid || await web_key_thumbprint(jwk as web_key_type)
  return public_from_private<alg, 'application/jwk+json'>({
    key: jwk as any,
    type: 'application/jwk+json'
  }) as fully_specified_web_key<alg>
}

export const export_private_web_key_with_algorithm = async <alg extends parseable_fully_specified_signature_algorithms>(
  k: KeyLike,
  alg: alg,
  kid?: string
): Promise<fully_specified_web_key<alg>> => {
  const jwk = await exportJWK(k);
  jwk.alg = alg
  jwk.ext = true; // impossible to export otherwise.
  jwk.kid = kid || await web_key_thumbprint(jwk as web_key_type)
  return format_web_key(jwk) as fully_specified_web_key<alg>
}

export const generate_web_key = async ({ alg, ext, kid }: {
  alg: fully_specified_signature_algorithms,
  ext: boolean,
  kid?: string
}) => {
  const lessSpecific = less_specified[alg]
  const k = await generateKeyPair(lessSpecific, { extractable: ext })
  return {
    publicKey: await export_public_web_key_with_algorithm(k.publicKey, alg, ext, kid),
    privateKey: await export_private_web_key_with_algorithm(k.privateKey, alg, kid),
  }
}

export const parse = <
  alg extends parseable_fully_specified_signature_algorithms,
  cty extends crypto_key_type
>({ key, type }: {
  key: Uint8Array,
  type: cty
}): parsable_fully_specified_keys<alg, cty> => {
  switch (type) {
    case 'application/jwk+json': {
      const jwk = JSON.parse(decoder.decode(key))
      return jwk
    }
    case 'application/cose-key': {
      return cbor.decode(key)
    }
    default: {
      throw new Error('Unknown key: ' + type)
    }
  }
}


export const generate = async ({ id, type, algorithm, extractable }: request_crypto_key): Promise<Buffer> => {
  switch (type) {
    case 'application/jwk+json': {
      const { privateKey } = await generate_web_key({ kid: id, alg: algorithm, ext: extractable || true })
      return Buffer.from(encoder.encode(JSON.stringify(privateKey)))
    }
    case 'application/cose-key': {
      const { privateKey } = await generate_web_key({ kid: id, alg: algorithm, ext: extractable || true })
      return convert({
        key: encoder.encode(JSON.stringify(privateKey)),
        from: 'application/jwk+json',
        to: 'application/cose-key'
      })
    }
    default: {
      throw new Error('Unsupported key type: ' + type)
    }
  }
}

export const convert = async ({ key, from, to }: { key: Uint8Array, from: crypto_key_type, to: crypto_key_type }) => {
  switch (from) {
    case 'application/jwk+json': {
      switch (to) {
        case 'application/cose-key': {
          const k = await web_key_to_cose_key(JSON.parse(decoder.decode(key)))
          return cbor.encode(k)
        }
        default: {
          throw new Error('Unknown key: ' + from)
        }
      }
    }
    default: {
      throw new Error('Unknown key: ' + from)
    }
  }
}

// generate parsed.
export const gen = async <
  alg extends parseable_fully_specified_signature_algorithms,
  cty extends crypto_key_type
>({ algorithm, type }: {
  algorithm: alg,
  type: cty
}): Promise<parsable_fully_specified_keys<alg, cty>> => {
  const key = await generate({ algorithm, type })
  return parse<alg, cty>({ key, type })
}


export const serialize = <
  alg extends parseable_fully_specified_signature_algorithms,
  cty extends crypto_key_type
>({ key, type }: { key: fully_specified_cose_key<alg> | fully_specified_web_key<alg>, type: cty }) => {
  if (type === 'application/jwk+json') {
    return Buffer.from(encoder.encode(JSON.stringify(format_web_key(key as JWK), null, 2)))
  }
  if (type === 'application/cose-key') {
    return cbor.encode(key)
  }
  throw new Error('Cannot serialize to unsupported media type: ' + type)
}