import { bufferToTruncatedBstr } from "../rfc/beautify/bufferToTruncatedBstr";
import { CoseKeyMap } from "./types";

import { addComment } from "../rfc/beautify/addComment";

const keySorter = (a: string, b: string) => {
  const aTag = parseInt(a.split(':')[0])
  const bTag = parseInt(b.split(':')[0])
  if (aTag >= 0 && bTag >= 0) {
    return aTag >= bTag ? 1 : -1
  } else {
    if (a.includes('[')) { // hack for x5c / x5t
      return 0
    }
    return aTag >= bTag ? -1 : 1
  }
}

export const beautify = (coseKey: CoseKeyMap): string => {
  const lines = [] as string[]
  const indentSpaces = ' '.repeat(2);
  for (const [key, value] of coseKey.entries()) {
    switch (key) {
      case 1: {
        lines.push(addComment(`${indentSpaces}${key}: ${value},`, 'Type'))
        break
      }
      case 2: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'Identifier'))
        break
      }
      case 3: {
        lines.push(addComment(`${indentSpaces}${key}: ${value},`, 'Algorithm'))
        break
      }
      case -1: {
        lines.push(addComment(`${indentSpaces}${key}: ${value},`, `Curve`))
        break
      }
      case -2: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'x public key component'))
        break
      }
      case -3: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'y public key component'))
        break
      }
      case -4: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'd private key component'))
        break
      }
      case -13: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'Post quantum private key'))
        break
      }
      case -14: {
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'Post quantum public key'))
        break
      }
      case -66666: {
        // x5c
        lines.push(addComment(`${indentSpaces}${key}: [`, 'X.509 Certificate Chain'))
        for (const cert of value as any) {
          lines.push(addComment(`${indentSpaces}  ${bufferToTruncatedBstr(cert)},`, 'X.509 Certificate'))
        }
        lines.push(`${indentSpaces}],`)
        break
      }
      case -66667: {
        // x5t (sha256)
        lines.push(addComment(`${indentSpaces}${key}: ${bufferToTruncatedBstr(value)},`, 'X.509 SHA-256 Thumbprint'))
        break
      }
      default: {
        throw new Error('Unsupported cose key value: ' + key)
      }
    }
  }
  return `
${addComment('{', 'COSE Key')}
${lines.sort(keySorter).join('\n')}
}
`.trim()
}

export const edn = beautify