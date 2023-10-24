import { addComment } from "./addComment"

import { bufferToTruncatedBstr } from './bufferToTruncatedBstr';

import { beautifyCoseSign1 } from "./beautifyCoseSign1";

import { default as tags } from '../../unprotectedHeader'


export const beautifyReceipts = async (receipts: Buffer[]) => {
  const blocks = [
    `${addComment(`        ${tags.scitt_receipt}: [`, `Receipts (${receipts.length})`)}
${receipts.map((receipt, i: number) => {
      const truncated = bufferToTruncatedBstr(receipt)
      return addComment(`          ${truncated}`, `Receipt ${i + 1}`)
    }).join('\n')}
        ]`]

  for (const receipt of receipts) {
    const receiptBlocks = await beautifyCoseSign1(receipt)
    receiptBlocks.forEach((rb) => {
      blocks.push(rb)
    })
  }
  return blocks
}