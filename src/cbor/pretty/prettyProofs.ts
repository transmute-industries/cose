

import * as cbor from 'cbor-web'

import { ellideBytes } from './ellideBytes'

import { rfc9162_sha256_proof_types, transparency } from '../../drafts/draft-ietf-cose-merkle-tree-proofs'
import { indentBlock } from './indentBlock'
export const prettyProof = (bytes: ArrayBuffer) => {
  const [size, index, path] = cbor.decode(bytes)
  return indentBlock(`<<[
  / size / ${size}, / leaf / ${index},
  / inclusion path / 
${path.map((p: ArrayBuffer) => {
    return '  ' + ellideBytes(p)
  }).join(',\n')}
]>>`, '  ')
}

export const prettyProofs = (proofs: Map<number, ArrayBuffer[]>) => {
  let result = ''
  for (const [label, value] of proofs.entries()) {
    switch (label) {
      case rfc9162_sha256_proof_types.inclusion: {
        result += `/ ${transparency.get(label)} / ${label} : [\n`
        for (const proof of value) {
          result += prettyProof(proof)
        }
        result += `\n],\n`
        break
      }
      default: {
        throw new Error('Unknown proof type')
      }
    }
  }

  return result.trim()

}