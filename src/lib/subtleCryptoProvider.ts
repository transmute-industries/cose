
// eslint-disable-next-line @typescript-eslint/no-empty-function
const nodeCrypto = import('crypto').catch(() => { })

export default async (): Promise<SubtleCrypto> => {
  try {
    return window.crypto.subtle
  } catch (e) {
    return (await (await nodeCrypto) as Crypto).subtle
  }
}