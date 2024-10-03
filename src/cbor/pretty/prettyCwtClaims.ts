import { indentBlock } from "./indentBlock"

import { cwt_claims } from "../../iana/assignments/cwt"

export const prettyCwtClaims = (claims: Map<any, any>) => {
  if (!(claims instanceof Map)) {
    return ''
  }
  let result = ``
  for (const [label, value] of claims.entries()) {
    switch (label) {
      case cwt_claims.iss: {
        result += indentBlock(`/ issuer  / ${label} : "${value}",`, '    ') + '\n'
        break
      }
      case cwt_claims.sub: {
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