import { encodeAsync } from "cbor-web"

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// eslint-disable-next-line @typescript-eslint/no-empty-function
const nodeCrypto = import('crypto').catch(() => { }) as any

export const COSE_Encrypt_Tag = 96


export const getRandomBytes = async (byteLength = 16) => {
  try {
    return crypto.getRandomValues(new Uint8Array(byteLength))
  } catch {
    return (await nodeCrypto).randomFillSync(new Uint8Array(byteLength))
  }
}


export async function createAAD(protectedHeader: BufferSource, context: any, externalAAD: BufferSource) {
  const encStructure = [
    context,
    protectedHeader,
    externalAAD
  ];
  return encodeAsync(encStructure);
}
