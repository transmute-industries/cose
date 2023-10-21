import { bufferToTruncatedBstr } from "../rfc/beautify/bufferToTruncatedBstr";
import { CoseKeyMap } from "./types";

import { addComment } from "../rfc/beautify/addComment";

const keySorter = (a: string, b: string) => {
  const aTag = parseInt(a.split(':')[0])
  const bTag = parseInt(b.split(':')[0])
  if (aTag >= 0 && bTag >= 0) {
    return aTag >= bTag ? 1 : -1
  } else {
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