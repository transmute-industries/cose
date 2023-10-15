
import { maxLineLength, commentOffset } from './constants'


export const addComment = (line: string, comment: string) => {
  let paddedComment = ' '.repeat(maxLineLength - commentOffset - line.length) + `/ ` + `${comment}`
  paddedComment = paddedComment + ' '.repeat(maxLineLength - line.length - paddedComment.length) + '/'
  return `${line}${paddedComment}`
}