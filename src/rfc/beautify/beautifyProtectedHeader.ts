import { addComment } from "./addComment"


import cbor from "../../cbor";
import { maxBstrTruncateLength } from './constants'

// https://www.iana.org/assignments/cose/cose.xhtml
const protectedHeaderTagToDescription = (tag: number) => {
  const descriptions = new Map();
  descriptions.set(1, 'Cryptographic algorithm to use')
  descriptions.set(2, 'Critical headers to be understood')
  descriptions.set(3, 'Content type of the payload')
  descriptions.set(4, 'Key identifier')
  return descriptions.get(tag) || `${tag} unknown cbor content`
}


export const beautifyProtectedHeader = async (data: Buffer | Uint8Array) => {
  const diagnostic = await cbor.web.diagnose(data)
  const mapItemSpacer = `  `
  let result = diagnostic;
  result = result.replace('{', `{\n${mapItemSpacer}`)
  result = result.replace(/, /g, `,\n${mapItemSpacer}`)
  result = result.replace('}', `\n}`)
  result = result.split('\n').map((line: string) => {
    if (line.trim() === '{') {
      line = addComment(`{`, `Protected header`)
      return line
    }
    if (line.includes(`h'`) && line.length > maxBstrTruncateLength) {
      line = line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`)
    }
    if (line === '' || line.trim() === '{' || line.trim() === '}') {
      return line
    }
    const maybeIntLabel = parseInt(line.split(':')[0], 10)
    return addComment(line, `${protectedHeaderTagToDescription(maybeIntLabel)}`)
  }).join('\n')
  return result
}
