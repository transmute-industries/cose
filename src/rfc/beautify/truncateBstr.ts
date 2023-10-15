
import cbor from '../../cbor'
import { maxBstrTruncateLength } from './constants'

export const truncateBstr = async (data: Buffer) => {
  let line = await cbor.web.diagnose(data)
  if (line.includes(`h'`) && line.length > maxBstrTruncateLength) {
    line = line.replace(/h'(.{8}).+(.{8})'/g, `h'$1...$2'`)
  }
  return line.trim()
}