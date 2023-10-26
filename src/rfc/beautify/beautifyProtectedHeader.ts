import { addComment } from "./addComment"


import cbor from "../../cbor";

import { bufferToTruncatedBstr } from "./bufferToTruncatedBstr";
import { default as tags } from "../../unprotectedHeader";


export const beautifyProtectedHeader = async (data: Buffer | Uint8Array) => {
  const protectedHeader = await cbor.web.decode(data)
  const lines = [] as string[]
  for (const [label, value] of protectedHeader.entries()) {
    if (label === 1) {
      lines.push(addComment(`  ${label}: ${value},`, 'Algorithm'))
    } else if (label === 2) {
      lines.push(addComment(`  ${label}: ${value},`, 'Criticality'))
    } else if (label === 3) {
      lines.push(addComment(`  ${label}: ${value},`, 'Content type'))
    } else if (label === 4) {
      lines.push(addComment(`  ${label}: ${bufferToTruncatedBstr(value)},`, 'Key identifier'))
    } else if (label === 13) {
      lines.push(addComment(`  ${label}: {`, 'CWT Claims'))
      for (const [claimKey, claimValue] of value.entries()) {
        if (claimKey === 1) {
          lines.push(addComment(`    ${claimKey}: ${claimValue},`, 'Issuer'))
        } else if (claimKey === 2) {
          lines.push(addComment(`    ${claimKey}: ${claimValue},`, 'Subject'))
        } else {
          lines.push(addComment(`    ${claimKey}: ${claimValue},`, 'Claim'))
        }
      }
      lines.push(`  },`)
    } else if (label === tags.verifiable_data_structure) {
      lines.push(addComment(`  ${label}: ${value},`, 'Verifiable Data Structure'))
    } else if (label === 33) {
      lines.push(addComment(`  ${label}: [`, 'X.509 Certificate Chain'))
      for (const cert of value) {
        lines.push(addComment(`    ${bufferToTruncatedBstr(cert)},`, 'X.509 Certificate'))
      }
      lines.push(`  ],`)
    } else {
      lines.push(addComment(`  ${label}: ${value},`, 'Parameter'))
    }

  }


  return `
${addComment('{', 'Protected')}
${lines.join('\n')}
}
  `.trim()
}
