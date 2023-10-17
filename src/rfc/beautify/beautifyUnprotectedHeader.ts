import { addComment } from "./addComment"

import unprotectedHeader from "../../unprotectedHeader"
import { beautifyInclusionProofs } from './beautifyInclusionProofs'
import { beautifyConsistencyProofs } from './beautifyConsistencyProofs'
import { beautifyReceipts } from './beautifyReceipts'

const labelMap = new Map()

labelMap.set(unprotectedHeader.inclusion_proof, beautifyInclusionProofs)
labelMap.set(unprotectedHeader.consistency_proof, beautifyConsistencyProofs)
labelMap.set(unprotectedHeader.receipt, beautifyReceipts)

export const beautifyUnprotectedHeader = async (unprotectedHeader: Map<number, unknown>) => {
  let allBlocks = [] as string[]
  let result = addComment(`      {},`, `Unprotected header`)
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
    const title = addComment(`      {`, `Unprotected header`)
    result = `${title}
${lines.join('      \n')}
      },`
  }

  return [result, ...allBlocks]
}