
import { base64url, JWK } from 'jose'
import { curve_to_label, ec2_params_to_labels, key_type_to_label } from '../iana/assignments/cose'
import { algorithms_to_labels } from '../iana/requested/cose'
import { jose_key_type, ec_web_key } from '../iana/assignments/jose'

export const web_key_to_cose_key = async <T>(jwk: JWK): Promise<T> => {
  const coseKey = new Map();
  const { kty } = jwk
  for (const [key, value] of Object.entries(jwk)) {
    switch (kty) {
      // todo key use and key_ops
      case jose_key_type.EC: {
        switch (key) {
          case ec_web_key.kty: {
            coseKey.set(ec2_params_to_labels.get(key), key_type_to_label.get(value as string))
            break;
          }
          case ec_web_key.crv: {
            coseKey.set(ec2_params_to_labels.get(key), curve_to_label.get(value as string))
            break;
          }
          case ec_web_key.alg: {
            const maybeUnknown = algorithms_to_labels.get(value as string) || value as string
            coseKey.set(ec2_params_to_labels.get(key), maybeUnknown)
            break;
          }
          case ec_web_key.kid: {
            coseKey.set(ec2_params_to_labels.get(key), value as string)
            break;
          }
          case ec_web_key.x:
          case ec_web_key.y:
          case ec_web_key.d: {
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

