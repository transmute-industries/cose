
import cbor from '../../cbor'

import { maxLineLength, commentOffset } from './constants'

const bufferToTruncatedBstr = (buf: Buffer) => {
  const line = `h'${buf.toString('hex').toLowerCase()}'`
  return line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`).trim()
}

const addComment = (line: string, comment: string) => {
  let paddedComment = ' '.repeat(maxLineLength - commentOffset - line.length) + `/ ` + `${comment}`
  paddedComment = paddedComment + ' '.repeat(maxLineLength - paddedComment.length - 4) + '/'
  return `${line}${paddedComment}`
}

const beautifyInclusionProof = async (data: Buffer) => {
  const [tree_size, leaf_index, audit_path] = await cbor.web.decode(data);
  const size = addComment(`  ${tree_size},`, `Transparency log length`)
  const leafIndex = addComment(`  ${leaf_index},`, `Leaf index`)
  const auditPaths = audit_path.map(bufferToTruncatedBstr).map((tp: string) => {
    return `     ${tp}           / Intermediate hash                     /`
  }).join('\n')

  return `
[
${size}
${leafIndex}
  [                                   / Inclusion path                        /
${auditPaths}
  ]

]
  `.trim()
}

export const beautifyInclusionProofs = async (value: Buffer) => {
  const proofs = cbor.web.decode(value)
  const truncatedProofs = [] as string[]
  const beautifulProofs = [] as string[]
  for (const p of proofs) {
    beautifulProofs.push(await beautifyInclusionProof(p))
    const line = `          ${bufferToTruncatedBstr(p)}      / inclusion proof                       /`
    truncatedProofs.push(line)
  }
  const line = `  100: [                        / inclusion proofs (${truncatedProofs.length})                  `.substring(0, 76) + '/'
  const headerTag = `${line}
${truncatedProofs}
        ]`


  return { headerTag, proofs: beautifulProofs }
}

/*

currently:

{
  100: [h'83040282...1f487bb1']
},

needs to be:

{
  100: [                         / inclusion proofs /
    [                            / inclusion proof /
      4,                         / tree size /
      2,                         / leaf index /
      [
        h'a39655d4...1f487bb1'   / audit path hash /
      ]
    ]
  ]
},

*/