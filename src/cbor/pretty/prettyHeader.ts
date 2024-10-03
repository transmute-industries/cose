

import { indentBlock } from "./indentBlock"

import { header, labels_to_algorithms } from "../../iana/assignments/cose"
import { draft_headers } from "../../iana/requested/cose"
import { transparency } from "../../drafts/draft-ietf-cose-merkle-tree-proofs"

import { prettyProofs } from "./prettyProofs"
import { ellideBytes } from "./ellideBytes"

import { prettyCwtClaims } from "./prettyCwtClaims"
import { prettyReceipts } from "./prettyReceipts"

export const prettyHeader = (map: Map<any, any> | object) => {
  if (!(map instanceof Map)) {
    return ''
  }
  let result = ``
  for (const [label, value] of map.entries()) {
    switch (label) {
      case header.kid: {
        const renered_key_id = typeof value === 'string' ? `"${value}"` : ellideBytes(value)
        result += indentBlock(`/ key / ${label} : ${renered_key_id},`, '    ') + '\n'
        break
      }
      case header.alg: {
        result += indentBlock(`/ algorithm / ${label} : ${value},  # ${labels_to_algorithms.get(value)}`, '    ') + '\n'
        break
      }
      case header.cwt_claims: {
        result += indentBlock(`/ claims / ${label} : {`, '    ') + '\n'
        result += indentBlock(prettyCwtClaims(value), '  ')
        result += `\n    },\n`
        break
      }
      case draft_headers.payload_hash_algorithm: {
        result += indentBlock(`/ hash  / ${label} : ${value}, # ${labels_to_algorithms.get(value)}`, '    ') + '\n'
        break
      }
      case draft_headers.payload_preimage_content_type: {
        result += indentBlock(`/ content  / ${label} : "${value}",`, '    ') + '\n'
        break
      }
      case draft_headers.payload_location: {
        result += indentBlock(`/ location / ${label} : "${value}",`, '    ') + '\n'
        break
      }
      case draft_headers.verifiable_data_structure: {
        result += indentBlock(`/ notary    / ${label} : ${value}, # ${transparency.get(value)}`, '    ') + '\n'
        break
      }
      case draft_headers.verifiable_data_proofs: {
        let proofs = ''
        proofs += `    / proofs / ${label} : {\n`
        proofs += indentBlock(prettyProofs(value), '      ')
        proofs += `\n    },\n`
        result += proofs
        break
      }
      case draft_headers.receipts: {
        let receipts = ''
        receipts += `    / receipts / ${label} : {\n`
        receipts += indentBlock(prettyReceipts(value), '      ')
        receipts += `\n    },\n`
        result += receipts
        break
      }
      default: {
        result += indentBlock(`${label}: ${value},`, '    ') + '\n'
      }
    }
  }
  result += ``
  return result
}