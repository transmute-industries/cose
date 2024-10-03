
import * as cbor from 'cbor-web'

import { prettyHeader } from './prettyHeader'
import { prettyPayload } from './prettyPayload'

import { ellideBytes } from './ellideBytes'

export const prettyCoseSign1 = (data: ArrayBuffer) => {
  const decoded = cbor.decode(data)
  const [encodedProtected, decodedUnprotected, encodedPayload, signature] = decoded.value
  const decodedProtected = cbor.decode(encodedProtected)
  return `
/ cose-sign1 / ${decoded.tag}([
  / protected   / <<{
${prettyHeader(decodedProtected)}
  }>>,
  / unprotected / {
${prettyHeader(decodedUnprotected)}
  },
  / payload     / ${prettyPayload(encodedPayload)}
  / signature   / ${ellideBytes(signature)}
])    
`

}

