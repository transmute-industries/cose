
import * as cbor from 'cbor-web'


import { diagnostic_types } from '../iana/assignments/media-types'

import { prettyCoseKey } from './pretty/prettyCoseKey'
import { prettyCose } from './pretty/prettyCose'

const removeBlankLines = (text: string) => {
    return text.replace(/(^[ \t]*\n)/gm, "")
}

export const diag = async (data: any, contentType: diagnostic_types) => {
    try {
        let text = ''
        if (contentType === 'application/cose-key') {
            text = await prettyCoseKey(data)
        }
        if (contentType === 'application/cose') {
            text = await prettyCose(data)
        }
        return removeBlankLines(text);

    } catch (e) {
        return cbor.diagnose(data)
    }
}


