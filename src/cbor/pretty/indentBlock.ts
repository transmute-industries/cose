export const indentBlock = (lines: string, padding: string) => {
  return lines.split('\n').map((line: string) => {
    return padding + line
  }).join('\n')
}