
import { maxLineLength, commentOffset } from './constants'

export const addComment = (line: string, comment: string) => {
  let linePrexiSpaces = maxLineLength - commentOffset - line.length
  if (linePrexiSpaces < 0) {
    linePrexiSpaces = 0;
  }
  let paddedComment = ' '.repeat(linePrexiSpaces) + `/ ` + `${comment}`

  const lineSuffixSpaces = maxLineLength - line.length - paddedComment.length

  paddedComment = paddedComment + ' '.repeat(lineSuffixSpaces) + '/'
  return `${line}${paddedComment}`
}