import { indentBlock } from "./indentBlock"
export const prettyCwtClaims = (claims: Map<any, any>) => {
  if (!(claims instanceof Map)) {
    return ''
  }
  let result = ``
  for (const [label, value] of claims.entries()) {
    switch (label) {
      case 1: {
        result += indentBlock(`/ issuer  / ${label} : "${value}",`, '    ') + '\n'
        break
      }
      case 2: {
        result += indentBlock(`/ subject / ${label} : "${value}",`, '    ') + '\n'
        break
      }
      default: {
        result += indentBlock(`${label}: ${value},`, '    ') + '\n'
      }
    }
  }
  return result
}