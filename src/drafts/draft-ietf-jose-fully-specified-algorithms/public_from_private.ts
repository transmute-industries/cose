import { fully_specified_cose_key, fully_specified_web_key } from ".";

import { JWK } from "jose";
import { jose_key_type, private_ec_web_key_params, private_okp_web_key_params, private_oct_web_key_params } from "../../iana/assignments/jose";

import { without_private_information } from ".";
import { crypto_key_type } from "../../iana/assignments/media-types";
import { any_cose_key, cose_key, cose_key_type, ec2, okp, symmetric } from "../../iana/assignments/cose";

import { parseable_fully_specified_signature_algorithms, parsable_fully_specified_keys } from ".";

export const public_from_private = <alg extends parseable_fully_specified_signature_algorithms, cty extends crypto_key_type>({ key, type }: {
  key: fully_specified_cose_key<alg> | fully_specified_web_key<alg>,
  type: cty
}): parsable_fully_specified_keys<alg, cty> => {
  if (type === 'application/jwk+json') {
    const jwk = key as JWK
    const { kty } = jwk
    switch (kty) {
      // RSA not supported at this time
      // case jose_key_type.RSA: {
      //   return without_private_information(key, private_rsa_web_key_params)
      // }
      case jose_key_type.EC: {
        return without_private_information(jwk, private_ec_web_key_params)
      }
      case jose_key_type.OKP: {
        return without_private_information(jwk, private_okp_web_key_params)
      }
      case jose_key_type.oct: {
        return without_private_information(jwk, private_oct_web_key_params)
      }
      default: {
        throw new Error('Unknown key type: ' + kty)
      }
    }
  }
  if (type === 'application/cose-key') {
    // Unlike JOSE, COSE does not have private information class on key parameters
    // So we are "guessing" regarding which parts of the IANA registry to omit.
    const pub = new Map((key as any_cose_key).entries())
    const kty = pub.get(cose_key.kty)
    switch (kty) {
      // RSA not supported at this time
      // case jose_key_type.RSA: {
      //   return without_private_information(key, private_rsa_web_key_params)
      // }
      case cose_key_type.ec2: {
        const deleted = pub.delete(ec2.d)
        if (!deleted) {
          throw new Error('Malformed EC2 Private Key (no d)')
        }
        return pub as parsable_fully_specified_keys<alg, cty>
      }
      case cose_key_type.okp: {
        const deleted = pub.delete(okp.d)
        if (!deleted) {
          throw new Error('Malformed OKP Private Key (no d)')
        }
        return pub as parsable_fully_specified_keys<alg, cty>
      }
      case cose_key_type.symmetric: {
        const deleted = pub.delete(symmetric.k)
        if (!deleted) {
          throw new Error('Malformed oct key (no k)')
        }
        return pub as parsable_fully_specified_keys<alg, cty>
      }
      default: {
        throw new Error('Unknown key type: ' + kty)
      }
    }
  }
  throw new Error("Unsupported key type: " + type)
}