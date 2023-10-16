
import cbor from '../../cbor'


import { addComment } from './addComment'

import { bufferToTruncatedBstr } from './bufferToTruncatedBstr'

const beautifyConsistencyProof = async (data: Buffer, index: number) => {
  const [tree_size_1, tree_size_2, consistency_path] = await cbor.web.decode(data);
  const size1 = addComment(`  ${tree_size_1},`, `Tree size 1`)
  const size2 = addComment(`  ${tree_size_2},`, `Tree size 2`)
  const auditPaths = consistency_path.map(bufferToTruncatedBstr).map((tp: string, index: number) => {
    return addComment(`     ${tp}`, `Intermediate hash ${index + 1}`)
  }).join('\n')

  return `
${addComment(`[`, `Consistency proof ${index + 1}`)}
${size1}
${size2}
${addComment(`  [`, `Consistency hashes (${consistency_path.length})`)}
${auditPaths}
  ]
]
  `.trim()
}

export const beautifyConsistencyProofs = async (proofs: Buffer[]) => {
  const truncatedProofs = [] as string[]
  const beautifulProofs = [] as string[]
  for (const p of proofs) {
    beautifulProofs.push(await beautifyConsistencyProof(p, beautifulProofs.length))
    const line = addComment(`          ${bufferToTruncatedBstr(p)},`, `Consistency proof ${beautifulProofs.length}`)
    truncatedProofs.push(line)
  }
  const line = addComment(`        200: [`, `Consistency proofs (${truncatedProofs.length})`)
  const headerTag = `${line}
${truncatedProofs.join("\n")}
        ]`
  return [headerTag, ...beautifulProofs]
}
