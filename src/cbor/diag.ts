
import * as cbor from 'cbor-web'


import { diagnostic_types } from '../iana/assignments/media-types'

import { prettyCoseKey } from './pretty/prettyCoseKey'
import { prettyCose } from './pretty/prettyCose'

export const diag = async (data: any, contentType: diagnostic_types) => {
    try {
        if (contentType === 'application/cose-key') {
            return prettyCoseKey(data)
        }
        if (contentType === 'application/cose') {
            return prettyCose(data)
        }
    } catch (e) {
        return cbor.diagnose(data)
    }
}


