
import * as jose from 'jose'
import { typedArrayToBuffer } from '../../utils'

import { IANACOSEKeyCommonParameters } from '../key-common-parameters';


export const convertJsonWebKeyToCoseKey = (jwk: Record<string, unknown>): Map<any, any> => {
  const coseKey = new Map();
  const commonParams = Object.values(IANACOSEKeyCommonParameters)
  for (const [key, value] of Object.entries(jwk)) {
    const foundCommonParam = commonParams.find((param) => {
      return param.Name === key
    })

    let label: string | number = key

    if (foundCommonParam) {
      label = parseInt(foundCommonParam.Label, 10)
    }

    console.log({ key, value, foundCommonParam })
    //   const coseKeyParam = keyUtils.parameters.toCOSE.get(key)
    switch (key) {
      case 'kty': {
        const coseKeyValue = keyUtils.types.toCOSE.get(value)
        coseKey.set(label, coseKeyValue)
        break
      }
      // case 'kid': {
      //   coseKey.set(coseKeyParam, value)
      //   break
      // }
      // case 'alg': {
      //   const coseKeyValue = keyUtils.algorithms.toCOSE.get(value)
      //   coseKey.set(coseKeyParam, coseKeyValue)
      //   break
      // }
      // case 'crv': {
      //   const coseKeyValue = keyUtils.curves.toCOSE.get(value)
      //   coseKey.set(coseKeyParam, coseKeyValue)
      //   break
      // }
      // case 'x': {
      //   // TODO: Length checks
      //   coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
      //   break
      // }
      // case 'y': {
      //   // TODO: Length checks
      //   coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
      //   break
      // }
      // case 'd': {
      //   // TODO: Length checks
      //   coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as string)))
      //   break
      // }
      // case 'use': {
      //   // console.log('skipping JWK use property when importing as COSE Key')
      //   break
      // }
      // case 'key_ops': {
      //   // console.log('skipping JWK use property when importing as COSE Key')
      //   break
      // }
      // case 'x5c': {
      //   const items = (value as string[] || []).map((item: string) => {
      //     return typedArrayToBuffer(jose.base64url.decode(item as string))
      //   })
      //   coseKey.set(coseKeyParam, items)
      //   break
      // }
      // case 'x5t#S256': {
      //   coseKey.set(coseKeyParam, typedArrayToBuffer(jose.base64url.decode(value as any)))
      //   break
      // }
      default: {
        // by default we assume a text label
        coseKey.set(label, value)
      }
    }
  }
  return coseKey
}


