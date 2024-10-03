
import { cose_key_to_web_key } from ".";

import { any_cose_key, crypto } from "../..";
import { web_key_type } from "../../iana/assignments/jose";

export const signer = async ({ key, algorithm }: { key: web_key_type | any_cose_key, algorithm: 'ES256' }) => {
  let privateKey
  if (key instanceof Map) {
    const jwk = await cose_key_to_web_key(key as any_cose_key)
    privateKey = await crypto.web.web_key_to_crypto_key(jwk, ['sign'])
  } else if ((key as web_key_type).kty) {
    privateKey = await crypto.web.web_key_to_crypto_key(key, ['sign'])
  }
  if (privateKey === undefined) {
    throw new Error('Unsupported key')
  }
  return crypto.web
    .signer({
      key: privateKey,
      algorithm
    })
}