
import { JWK, base64url } from 'jose'
import { typedArrayToBuffer } from '../../utils'

import { IANACOSEKeyCommonParameters } from '../key-common-parameters';
import { IANACOSEAlgorithms } from '../algorithms';
import { IANACOSEKeyTypeParameters, IANACOSEKeyTypeParameter } from '../key-type-parameters';
import { IANACOSEKeyTypes } from '../key-type';
import { IANACOSEEllipticCurves } from '../elliptic-curves';


const algorithms = Object.values(IANACOSEAlgorithms)
const commonParams = Object.values(IANACOSEKeyCommonParameters)
const keyTypeParams = Object.values(IANACOSEKeyTypeParameters)
const keyTypes = Object.values(IANACOSEKeyTypes)
const curves = Object.values(IANACOSEEllipticCurves)


const keyTypeParamsByKty = {
  'OKP': keyTypeParams.filter((p) => p['Key Type'] === '1'),
  'EC2': keyTypeParams.filter((p) => p['Key Type'] === '2')
} as Record<'OKP' | 'EC2', IANACOSEKeyTypeParameter[]>

const getKeyTypeSpecificLabel = (keyType: 'EC2' | 'OKP', keyTypeParam: string) => {
  let label: string | number = keyTypeParam;
  let foundKeyTypeParam = keyTypeParamsByKty[keyType].find((param) => {
    return param.Name === keyTypeParam
  })
  if (!foundKeyTypeParam) {
    foundKeyTypeParam = keyTypeParamsByKty[keyType].find((param) => {
      return param.Name === keyTypeParam
    })
  }
  if (foundKeyTypeParam) {
    label = parseInt(foundKeyTypeParam.Label, 10)
  } else {
    throw new Error(`Unable to find a label for this param (${keyTypeParam}) for the given key type ${keyType}`)
  }
  return label
}

export const convertJsonWebKeyToCoseKey = (jwk: JWK): Map<any, any> => {

  const { kty } = jwk
  let coseKty = `${kty}` as 'OKP' | 'EC' | 'EC2'; // evidence of terrible design.
  if (coseKty === 'EC') {
    coseKty = 'EC2'
  }
  if (!keyTypeParamsByKty[coseKty]) {
    throw new Error('Unsupported key type')
  }
  const coseKey = new Map();

  for (const [key, value] of Object.entries(jwk)) {
    const foundCommonParam = commonParams.find((param) => {
      return param.Name === key
    })
    let label: string | number = key
    if (foundCommonParam) {
      label = parseInt(foundCommonParam.Label, 10)
    }
    switch (key) {
      case 'kty': {
        const foundKeyType = keyTypes.find((param) => {
          return param.Name === coseKty
        })
        if (foundKeyType) {
          coseKey.set(label, parseInt(foundKeyType.Value, 10))
        } else {
          throw new Error('Unsupported key type: ' + value)
        }
        break
      }
      case 'kid': {
        if (foundCommonParam) {
          coseKey.set(label, value)
        } else {
          throw new Error('Expected common parameter was not found in iana registry.')
        }
        break
      }
      case 'alg': {
        if (foundCommonParam) {
          const foundAlgorithm = algorithms.find((param) => {
            return param.Name === value
          })
          if (foundAlgorithm) {
            coseKey.set(label, parseInt(foundAlgorithm.Value, 10))
          } else {
            throw new Error('Expected algorithm was not found in iana registry.')
          }
        } else {
          throw new Error('Expected common parameter was not found in iana registry.')
        }
        break
      }
      case 'crv': {
        label = getKeyTypeSpecificLabel(coseKty, 'crv')
        const foundCurve = curves.find((param) => {
          return param.Name === value
        })
        if (foundCurve) {
          coseKey.set(label, parseInt(foundCurve.Value, 10))
        } else {
          throw new Error('Expected curve was not found in iana registry.')
        }
        break
      }
      case 'x':
      case 'y':
      case 'd': {
        label = getKeyTypeSpecificLabel(coseKty, key)
        coseKey.set(label, typedArrayToBuffer(base64url.decode(value as string)))
        break
      }
      case 'x5c': {
        const items = (value as string[] || []).map((item: string) => {
          return typedArrayToBuffer(base64url.decode(item as string))
        })
        coseKey.set(label, items)
        break
      }
      case 'x5t#S256': {
        coseKey.set(label, typedArrayToBuffer(base64url.decode(value as string)))
        break
      }
      default: {
        // by default we assume a text label
        coseKey.set(label, value)
      }
    }
  }



  // TODO: Length checks on x, y, d
  return coseKey
}


