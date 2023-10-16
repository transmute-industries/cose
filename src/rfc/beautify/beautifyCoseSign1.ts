import cbor from '../../cbor'


import { bufferToTruncatedBstr } from './bufferToTruncatedBstr';
import { addComment } from './addComment'

import { beautifyUnprotectedHeader } from './beautifyUnprotectedHeader';
import { beautifyProtectedHeader } from './beautifyProtectedHeader';

export const beautifyCoseSign1 = async (data: Uint8Array): Promise<string[]> => {
  const decoded = await cbor.web.decode(data);
  const protectedHeaderLine = `      ${bufferToTruncatedBstr(decoded.value[0])},`
  const [unprotectedHeaderLines, ...unprotectedHeaderBlocks] = await beautifyUnprotectedHeader(decoded.value[1])
  const payloadLine = `      ${bufferToTruncatedBstr(decoded.value[2])},`
  const signatureLine = `      ${bufferToTruncatedBstr(decoded.value[3])}`
  const envelope = `
18(                                 / COSE Single Signer Data Object        /
    [
${addComment(protectedHeaderLine, 'Protected header')}
${unprotectedHeaderLines}
${addComment(payloadLine, decoded.value[2].length > 0 ? `Payload` : `Detached payload`)}
${addComment(signatureLine, 'Signature')}
    ]
)
`.trim()

  const envelopeHeader = await beautifyProtectedHeader(decoded.value[0])
  return [envelope, envelopeHeader, ...unprotectedHeaderBlocks]
}

