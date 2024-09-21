import { base64url } from "jose";
import { formatJwk } from "./formatJwk";
import { labels_to_ec2_params, ec2, label_to_key_type, any_cose_key, label_to_curve } from '../../iana/assignments/cose'
import { labels_to_algorithms } from "../../iana/requested/cose";

export const convertCoseKeyToJsonWebKey = async <T>(key: any_cose_key): Promise<T> => {

  const jwk = {} as Record<string, any>
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
  return formatJwk(jwk) as T
}