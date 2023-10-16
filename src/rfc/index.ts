import cbor from '../cbor'

import { beautifyCoseSign1 } from './beautify/beautifyCoseSign1'

import { makeRfcCodeBlock } from './beautify/makeRfcCodeBlock';

const beautify = async (data: Uint8Array) => {
  const decoded = await cbor.web.decode(data);
  if (decoded.tag === 18) {
    return beautifyCoseSign1(data)
  }
  throw new Error('Unsupported cbor tag.')
}

const rfc = {
  diag: async (data: Uint8Array) => {
    return beautify(data)
  },
  blocks: (diagnostic: string[]) => {
    return diagnostic.map(makeRfcCodeBlock).join('\n\n')
  }
}

export default rfc