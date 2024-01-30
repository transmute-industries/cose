
import rfc from "../../rfc"

export const edn = async (receipt: ArrayBuffer) => {
  const proofBlocks = await rfc.diag(new Uint8Array(receipt))
  return rfc.blocks(proofBlocks)
}