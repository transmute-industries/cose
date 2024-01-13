
import { base64url } from "jose";
import { createHash } from 'crypto'

import cose from '../../../src'

const urnPrefix = `urn:ietf:params:scitt`
const nodeCryptoHashFunction = 'sha256'
const mandatoryBaseEncoding = `base64url` // no pad .

// https://www.iana.org/assignments/named-information/named-information.xhtml
const nodeCryptoToIanaNamedHashFunctions = {
  [nodeCryptoHashFunction]: 'sha-256'
}

export const urn = (type: string, message: Buffer) => {
  if (['statement', 'transparent-statement'].includes(type)) {
    const messageHashBase64 = base64url.encode(createHash(nodeCryptoHashFunction).update(message).digest());
    const scittUrn = `${urnPrefix}:${type}:${nodeCryptoToIanaNamedHashFunctions[nodeCryptoHashFunction]}:${mandatoryBaseEncoding}:${messageHashBase64}`
    return scittUrn;
  } else {
    const tbs = cose.extractTBS(message)
    const messageHashBase64 = base64url.encode(createHash(nodeCryptoHashFunction).update(tbs).digest());
    const scittUrn = `${urnPrefix}:${type}:${nodeCryptoToIanaNamedHashFunctions[nodeCryptoHashFunction]}:${mandatoryBaseEncoding}:${messageHashBase64}`
    return scittUrn
  }
}