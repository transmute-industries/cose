
import { prettyCoseSign1 } from "./prettyCoseSign1"

export const prettyReceipts = (receipts: Buffer[]) => {

  return receipts.map((r: any) => {
    return `<<${prettyCoseSign1(Buffer.from(r)).trim()}>>`
  }).join(',\n')

}