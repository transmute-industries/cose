

import { indentBlock } from "./indentBlock"

import { header, labels_to_algorithms } from "../../iana/assignments/cose"

export const prettyHeader = (map: Map<any, any> | object) => {
  if (!(map instanceof Map)) {
    return '{},'
  }
  let result = ``
  for (const [label, value] of map.entries()) {
    switch (label) {
      case header.alg: {
        result += indentBlock(`/ algorithm / ${label} : ${value}, # ${labels_to_algorithms.get(value)}`, '    ')
        break
      }
      default: {
        result += indentBlock(`${label}: ${value},`, '    ')
      }
    }
  }
  result += ``
  return result
}