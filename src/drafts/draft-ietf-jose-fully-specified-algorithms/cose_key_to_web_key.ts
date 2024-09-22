import { base64url, JWK } from "jose";

import { labels_to_ec2_params, ec2, label_to_key_type, any_cose_key, label_to_curve } from '../../iana/assignments/cose'
import { labels_to_algorithms } from "../../iana/requested/cose";


import { format_web_key } from ".";

export const cose_key_to_web_key = async <T>(key: any_cose_key): Promise<T> => {

  const jwk = {} as JWK // this should error kty is mandatory
  const ktyLabel = key.get(ec2.kty)
  const kty = labels_to_ec2_params.get(ktyLabel)
  if (!kty) {
    throw new Error('Unknown cose key type: ' + ktyLabel)
  }
  for (const [label, value] of key.entries()) {
    switch (label) {
      case ec2.kty: {
        const key = labels_to_ec2_params.get(label)
        jwk[`${key}`] = label_to_key_type.get(value)
        break
      }
      case ec2.kid: {
        const key = labels_to_ec2_params.get(label)
        jwk[`${key}`] = value
        break
      }
      case ec2.alg: {
        const key = labels_to_ec2_params.get(label)
        jwk[`${key}`] = labels_to_algorithms.get(value)
        break
      }
      case ec2.crv: {
        const key = labels_to_ec2_params.get(label)
        jwk[`${key}`] = label_to_curve.get(value)
        break
      }
      case ec2.x:
      case ec2.y:
      case ec2.d: {
        const key = labels_to_ec2_params.get(label)
        jwk[`${key}`] = base64url.encode(value)
        break
      }
      default: {
        jwk[label] = value
      }
    }
  }
  return format_web_key(jwk) as T
}