
import cbor from '../../cbor'


import { addComment } from './addComment'

import { bufferToTruncatedBstr } from './bufferToTruncatedBstr'

const beautifyInclusionProof = async (data: Buffer, index: number) => {
  const [tree_size, leaf_index, audit_path] = await cbor.web.decode(data);
  const size = addComment(`  ${tree_size},`, `Tree size`)
  const leafIndex = addComment(`  ${leaf_index},`, `Leaf index`)
  const auditPaths = audit_path.map(bufferToTruncatedBstr).map((tp: string, index: number) => {
    return addComment(`     ${tp}`, `Intermediate hash ${index + 1}`)
  }).join('\n')

  return `
${addComment(`[`, `Inclusion proof ${index + 1}`)}
${size}
${leafIndex}
${addComment(`  [`, `Inclusion hashes (${audit_path.length})`)}
${auditPaths}
  ]
]
  `.trim()
}

export const beautifyInclusionProofs = async (proofs: Buffer[]) => {
  const truncatedProofs = [] as string[]
  const beautifulProofs = [] as string[]
  for (const p of proofs) {
    beautifulProofs.push(await beautifyInclusionProof(p, beautifulProofs.length))
    const line = addComment(`          ${bufferToTruncatedBstr(p)},`, `Inclusion proof ${beautifulProofs.length}`)
    truncatedProofs.push(line)
  }
  const line = addComment(`        100: [`, `Inclusion proofs (${truncatedProofs.length})`)
  const headerTag = `${line}
${truncatedProofs.join("\n")}
        ]`
  return [headerTag, ...beautifulProofs]
}
