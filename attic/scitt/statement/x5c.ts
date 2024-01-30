
import cbor from "../../cbor";

export const x5c = (coseSign1: ArrayBuffer): string[] => {
  const decoded = cbor.decode(coseSign1)
  const decodedProtectedHeader = cbor.decode(decoded.value[0])
  const certs = decodedProtectedHeader.get(33) // x5c in protected header
  const baseEncoded = (certs as Buffer[]).map((c: Buffer) => {
    return c.toString('base64')
  })
  return baseEncoded
}
