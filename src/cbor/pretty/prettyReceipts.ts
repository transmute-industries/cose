
import { toArrayBuffer } from "../toArrayBuffer"
import { prettyCoseSign1 } from "./prettyCoseSign1"

export const prettyReceipts = (receipts: ArrayBuffer[]) => {

  return receipts.map((r: any) => {
    return `<<${prettyCoseSign1(toArrayBuffer(r)).trim()}>>`
  }).join(',\n')

}