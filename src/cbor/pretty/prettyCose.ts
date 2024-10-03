import * as cbor from 'cbor-web'
import { prettyCoseSign1 } from './prettyCoseSign1'

export const prettyCose = (data: ArrayBuffer) => {
  const decoded = cbor.decode(data)
  if (decoded.tag === 18) {
    return prettyCoseSign1(data)
  }
  return cbor.diagnose(data)
}

