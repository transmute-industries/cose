import cbor from '../cbor'

import { beautifyCoseSign1 } from './beautify/cose-sign-1'

const beautify = async (data: Buffer | Uint8Array) => {
  const decoded = await cbor.web.decode(data);
  if (decoded.tag === 18) {
    return beautifyCoseSign1(data)
  }
  throw new Error('Unsupported cbor tag.')
}

const rfc = {
  diag: async (data: Buffer | Uint8Array) => {
    return beautify(data)
  }
}

export default rfc