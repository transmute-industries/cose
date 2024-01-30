import { addComment } from "./addComment"

import { default as tags } from '../../unprotectedHeader'

import { beautifyInclusionProofs } from './beautifyInclusionProofs'
import { beautifyConsistencyProofs } from './beautifyConsistencyProofs'

import verifiable_data_structure_proofs from "../../verifiable_data_structure_proofs"
const labelMap = new Map()

labelMap.set(verifiable_data_structure_proofs.inclusion_proof, beautifyInclusionProofs)
labelMap.set(verifiable_data_structure_proofs.consistency_proof, beautifyConsistencyProofs)

export const beautifyVerifiableProofs = async (unprotectedHeader: Map<number, unknown>) => {
  let allBlocks = [] as string[]
  let result = addComment(`        {},`, `Proofs`)
  if (unprotectedHeader.size) {
    let lines = [] as string[]
    for (const [key, value] of unprotectedHeader.entries()) {
      const processor = labelMap.get(key)
      if (!processor) {
        console.log('unknown ', key, value)
        continue
      }
      const [primaryLine, ...otherBlocks] = await processor(value)
      lines = [...lines, primaryLine]
      allBlocks = [...allBlocks, ...otherBlocks]
    }
    const title = addComment(`        ${tags.verifiable_data_structure_proofs}: {`, `Proofs`)
    result = `${title}
${lines.join('      \n')}
        },`
  }

  return [result, ...allBlocks]
}