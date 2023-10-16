import { addComment } from "./addComment"

import { beautifyInclusionProofs } from './beautifyInclusionProofs'
import { beautifyReceipts } from './beautifyReceipts'

const labelMap = new Map()

labelMap.set(100, beautifyInclusionProofs) // encoding is weird...
labelMap.set(300, beautifyReceipts)

export const beautifyUnprotectedHeader = async (unprotectedHeader: Map<number, unknown>) => {
  let allBlocks = [] as string[]
  let result = addComment(`    {},`, `Unprotected header`)
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