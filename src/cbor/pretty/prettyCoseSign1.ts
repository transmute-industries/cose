
import * as cbor from 'cbor-web'

export const prettyCoseSign1 = (data: Buffer) => {
    return cbor.diagnose(data)
}

