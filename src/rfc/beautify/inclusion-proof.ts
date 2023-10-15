
import cbor from '../../cbor'


import { addComment } from './addComment'

import { bufferToTruncatedBstr } from './bufferToTruncatedBstr'

const beautifyInclusionProof = async (data: Buffer) => {
  const [tree_size, leaf_index, audit_path] = await cbor.web.decode(data);
  const size = addComment(`  ${tree_size},`, `Tree size`)
  const leafIndex = addComment(`  ${leaf_index},`, `Leaf index`)
  const auditPaths = audit_path.map(bufferToTruncatedBstr).map((tp: string) => {
    return addComment(`     ${tp}`, `Intermediate hash`)
  }).join('\n')

  return `
${addComment(`[`, `Inclusion proof`)}
${size}
${leafIndex}
${addComment(`  [`, `Inclusion path (${audit_path.length})`)}
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
    const line = addComment(`          ${bufferToTruncatedBstr(p)}`, 'Inclusion proof')
    truncatedProofs.push(line)
  }
  const line = addComment(`        100: [`, `Inclusion proofs (${truncatedProofs.length})`)
  const headerTag = `${line}
${truncatedProofs}
        ]`
  return { headerTag, proofs: beautifulProofs }
}

/*
~~~~ cbor-diag
[                                     / Inclusion proof                       /
  4,                                  / Tree size                             /
  2,                                  / Leaf index                            /
  [                                   / Inclusion path                        /
      h'a39655d4...d29a968a'          / Intermediate hash                     /
      h'57187dff...1f487bb1'          / Intermediate hash                     /
  ]
]
~~~~

~~~~ cbor-diag
{                                     / Protected header                      /
  1: -7,                              / Cryptographic algorithm to use        /
  4: h'68747470...6d706c65'           / Key identifier                        /
}
~~~~

~~~~ cbor-diag
18(                                   / COSE Single Signer Data Object        /
    [
      h'a2012604...6d706c65',         / Protected header encoded as bstr      /
      {
        100: [                        / inclusion proofs (1)                  /
          h'83040282...1f487bb1'      / inclusion proof                       /
        ]
      },
      h'',                            / Content of the message as bstr or nil /
      h'efde9a59...b4cb142b'          / Signature value as bstr               /
    ]
)
~~~~
*/