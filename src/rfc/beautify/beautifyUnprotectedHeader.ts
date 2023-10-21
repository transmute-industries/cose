import { addComment } from "./addComment"

import unprotectedHeader from "../../unprotectedHeader"
import { beautifyVerifiableProofs } from './beautifyVerifiableProofs'
import { beautifyReceipts } from './beautifyReceipts'

const labelMap = new Map()

labelMap.set(unprotectedHeader.verifiable_data_structure_proofs, beautifyVerifiableProofs)
labelMap.set(unprotectedHeader.scitt_receipt, beautifyReceipts)

// labelMap.set(unprotectedHeader.inclusion_proof, beautifyInclusionProofs)
// labelMap.set(unprotectedHeader.consistency_proof, beautifyConsistencyProofs)

export const beautifyUnprotectedHeader = async (unprotectedHeader: Map<number, unknown>) => {
  let allBlocks = [] as string[]
  let result = addComment(`      {},`, `Unprotected`)
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
    const title = addComment(`      {`, `Unprotected`)
    result = `${title}
${lines.join('      \n')}
      },`
  }

  return [result, ...allBlocks]
}