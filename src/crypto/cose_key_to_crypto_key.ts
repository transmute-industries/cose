import { any_cose_key, cose_key, cose_key_type } from "../iana/assignments/cose"
import { cose_key_to_web_key } from "./key"
import { web_key_to_crypto_key } from "./web_key_to_crypto_key"

export const cose_key_to_crypto_key = async (key: any_cose_key): Promise<CryptoKey> => {
  if (key.get(cose_key.kty) != cose_key_type.ec2) {
    throw new Error('Only EC2 keys are supported')
  }
  const jwk = await cose_key_to_web_key<any>(key)
  return web_key_to_crypto_key(jwk)
}