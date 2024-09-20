
import { base64url } from 'jose'

import { curve_to_label, ec2_params_to_labels, key_type_to_label } from '../../iana/assignments/cose'

import { algorithms_to_labels } from '../../iana/requested/cose'

export const convertJsonWebKeyToCoseKey = async <T>(jwk: any): Promise<T> => {
  const coseKey = new Map();
  const { kty } = jwk
  for (const [key, value] of Object.entries(jwk)) {
    switch (kty) {
      case 'EC': {
        switch (key) {
          case 'kty': {
            coseKey.set(ec2_params_to_labels.get(key), key_type_to_label.get(value as string))
            break;
          }
          case 'crv': {
            coseKey.set(ec2_params_to_labels.get(key), curve_to_label.get(value as string))
            break;
          }
          case 'alg': {
            const maybeUnknown = algorithms_to_labels.get(value as string) || value as string
            coseKey.set(ec2_params_to_labels.get(key), maybeUnknown)
            break;
          }
          case 'kid': {
            coseKey.set(ec2_params_to_labels.get(key), value as string)
            break;
          }
          case 'x':
          case 'y':
          case 'd': {
            // todo check lengths based on curves
            coseKey.set(ec2_params_to_labels.get(key), Buffer.from(base64url.decode(value as string)))
            break;
          }
          default: {
            coseKey.set(key, value)
          }
        }
        break;
      }
      default: {
        coseKey.set(key, value)
      }
    }
  }
  return coseKey as T
}

// coseKey.set(label, Buffer.from(base64url.decode(value as string)))

