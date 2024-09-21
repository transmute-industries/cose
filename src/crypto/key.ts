


import * as cbor from 'cbor-web'

import { crypto_key_type } from '../iana/assignments/media-types'
import { fully_specified_signature_algorithms, generate_web_key } from "../drafts/draft-ietf-jose-fully-specified-algorithms"

import { web_key_to_cose_key } from './web_key_to_cose_key'
import { parse } from "../drafts/draft-ietf-jose-fully-specified-algorithms";

export { parse }
const encoder = new TextEncoder()
const decoder = new TextDecoder()

export type request_crypto_key = {

  type: crypto_key_type,
  algorithm: fully_specified_signature_algorithms

  id?: string,
  extractable?: boolean
}

export const generate = async ({ id, type, algorithm, extractable }: request_crypto_key) => {
  switch (type) {
    case 'application/jwk+json': {
      const { privateKey } = await generate_web_key({ kid: id, alg: algorithm, ext: extractable || true })
      return encoder.encode(JSON.stringify(privateKey))
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
