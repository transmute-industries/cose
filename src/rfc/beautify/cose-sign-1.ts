import cbor from '../../cbor'


import { makeRfcCodeBlock } from './makeRfcCodeBlock'
import { maxBstrTruncateLength, maxLineLength, commentOffset } from './constants'

import { beautifyInclusionProofs } from './inclusion-proof'

// https://www.iana.org/assignments/cose/cose.xhtml
const protectedHeaderTagToDescription = (tag: number) => {
  const descriptions = new Map();
  descriptions.set(1, 'Cryptographic algorithm to use')
  descriptions.set(2, 'Critical headers to be understood')
  descriptions.set(3, 'Content type of the payload')
  descriptions.set(4, 'Key identifier')
  return descriptions.get(tag) || `${tag} unknown cbor content`
}

const beautifyProtectedHeader = async (data: Buffer | Uint8Array) => {
  const diagnostic = await cbor.web.diagnose(data)
  const mapItemSpacer = `  `
  let result = diagnostic;
  result = result.replace('{', `{\n${mapItemSpacer}`)
  result = result.replace(/, /g, `,\n${mapItemSpacer}`)
  result = result.replace('}', `\n}`)
  result = result.split('\n').map((line: string) => {
    if (line.trim() === '{') {
      line = `{                                     / Protected header                      /`
      return line
    }
    if (line.includes(`h'`) && line.length > maxBstrTruncateLength) {
      line = line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`)
    }
    if (line === '' || line.trim() === '{' || line.trim() === '}') {
      return line
    }
    const maybeIntLabel = parseInt(line.split(':')[0], 10)
    const commentPlaceholder = `/ ${protectedHeaderTagToDescription(maybeIntLabel)}`
    const commentSpacer = maxLineLength - line.length - commentOffset
    const lineWithComment = line + ' '.repeat(commentSpacer) + commentPlaceholder
    return lineWithComment + ' '.repeat(maxLineLength - lineWithComment.length) + `/`
  }).join('\n')
  return result
}

const coseSign1IndexToDescription = (index: number) => {
  const descriptions = new Map();
  descriptions.set(0, 'COSE Single Signer Data Object')
  descriptions.set(2, 'Protected header encoded as bstr')
  descriptions.set(3, 'Unprotected header as a map')
  descriptions.set(4, 'Content of the message as bstr or nil')
  descriptions.set(5, 'Signature value as bstr')
  return descriptions.get(index) || `${index} unknown cbor content`
}



const beautifyUnprotectedHeader = async (unprotectedHeader: Map<number, unknown>) => {
  const blocks = [] as string[]
  let result = "      {},                     / Unprotected header as a map           /"
  if (unprotectedHeader.size) {
    const lines = []
    for (const [key, value] of unprotectedHeader.entries()) {
      if (key === 100) {
        const result = await beautifyInclusionProofs(value as Buffer)
        lines.push(result.headerTag)
        for (const p of result.proofs) {
          blocks.push(makeRfcCodeBlock(p))
        }
      } else {
        console.log('unknown tag ', key)
      }
    }
    result = `      {
      ${lines.join('      \n')}
      },`
  }

  return { prettyUnprotectedHeader: result, blocks }
}

const beautifyCoseSign1Object = async (data: Buffer | Uint8Array) => {
  const allBlocks = [] as string[]
  const decoded = await cbor.web.decode(data);
  const diagnostic = await cbor.web.diagnose(data)
  const tagSpacer = `    `;
  const arraySpacer = `${tagSpacer}  `
  let result = diagnostic;
  result = result.replace('([', `(\n${tagSpacer}[\n${arraySpacer}`)
  result = result.replace(/, /g, `,\n${arraySpacer}`)
  result = result.replace('])', `\n${tagSpacer}]\n)`)
  result = await Promise.all(result.split('\n').map(async (line: string, index: number) => {
    if (line.includes(`h'`) && line.length > maxBstrTruncateLength) {
      line = line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`)
    }
    if (line === '' || line.includes('[') || line.includes(']') || line.trim() === ')') {
      return line
    }
    if (index === 3) {
      const { prettyUnprotectedHeader, blocks } = await beautifyUnprotectedHeader(decoded.value[1])
      for (const b of blocks) {
        allBlocks.push(b)
      }
      return prettyUnprotectedHeader
    }
    const commentPlaceholder = `/ ${coseSign1IndexToDescription(index)}`
    let commentSpacer = maxLineLength - line.length - commentOffset
    commentSpacer = commentSpacer > 0 ? commentSpacer : 1
    const lineWithComment = line + ' '.repeat(commentSpacer) + commentPlaceholder
    return lineWithComment + ' '.repeat(maxLineLength - lineWithComment.length) + `/`
  }))
  result = result.join('\n')
  return { envelope: result, blocks: allBlocks }
}

export const beautifyCoseSign1 = async (data: Buffer | Uint8Array) => {
  const decoded = await cbor.web.decode(data);
  const [encodedProtectedHeader] = decoded.value
  const protectedHeader = await beautifyProtectedHeader(encodedProtectedHeader)
  const { envelope, blocks } = await beautifyCoseSign1Object(data)
  return [...blocks, makeRfcCodeBlock(protectedHeader), makeRfcCodeBlock(envelope)].join('\n\n')
}

