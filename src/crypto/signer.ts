
import { toArrayBuffer } from '../cbor'
import { SecretKeyJwk } from '../cose/sign1'

import subtleCryptoProvider from './subtleCryptoProvider'

import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

const signer = ({ privateKeyJwk }: { privateKeyJwk: SecretKeyJwk }) => {
  const digest = getDigestFromVerificationKey(`${privateKeyJwk.alg}`)
  return {
    sign: async (toBeSigned: ArrayBuffer): Promise<ArrayBuffer> => {
      const subtle = await subtleCryptoProvider()
      const signingKey = await subtle.importKey(
        "jwk",
        privateKeyJwk,
        {
          name: "ECDSA",
          namedCurve: privateKeyJwk.crv,
        },
        true,
        ["sign"],
      )
      const signature = await subtle.sign(
        {
          name: "ECDSA",
          hash: { name: digest },
        },
        signingKey,
        toBeSigned,
      );

      return toArrayBuffer(signature);
    }
  }
}

export default signer