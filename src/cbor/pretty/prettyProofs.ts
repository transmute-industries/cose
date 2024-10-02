

import * as cbor from 'cbor-web'

import { ellideBytes } from './ellideBytes'

import { rfc9162_sha256_proof_types, transparency } from '../../drafts/draft-ietf-cose-merkle-tree-proofs'
import { indentBlock } from './indentBlock'

export const prettyInclusionProof = (proof: ArrayBuffer | [number, number, Buffer[]]) => {
  const [size, index, path] = Array.isArray(proof) ? proof : cbor.decode(proof)
  return indentBlock(`<<[
  / size / ${size}, / leaf / ${index},
  / inclusion path / 
${path.length === 0 ? '  []' : path.map((p: ArrayBuffer) => {
    return '  ' + ellideBytes(p)
  }).join(',\n')}
]>>`, '  ')
}

export const prettyConsistencyProof = (proof: ArrayBuffer | [number, number, Buffer[]]) => {
  const [size1, size2, path] = Array.isArray(proof) ? proof : cbor.decode(proof)

  return indentBlock(`<<[
  / old / ${size1}, / new / ${size2},
  / consistency path / 
${path.length === 0 ? '  []' : path.map((p: ArrayBuffer) => {
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
          result += prettyInclusionProof(proof)
        }
        result += `\n],\n`
        break
      }
      case rfc9162_sha256_proof_types.consistency: {
        result += `/ ${transparency.get(label)} / ${label} : [\n`
        for (const proof of value) {
          result += prettyConsistencyProof(proof)
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