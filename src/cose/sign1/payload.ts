
import { decodeFirst, encode } from '../../cbor'



export const attach = async (coseSign1Bytes: ArrayBuffer, payload: ArrayBuffer) => {
  const obj = await decodeFirst(coseSign1Bytes);
  const signatureStructure = obj.value;
  const [protectedHeaderBytes, unprotectedHeader, currentPayload, signature] = signatureStructure;
  if (currentPayload !== null) {
    throw new Error('Payload is already attached')
  }
  const attached = encode(['Signature1', protectedHeaderBytes, unprotectedHeader, payload, signature]);
  return attached
}