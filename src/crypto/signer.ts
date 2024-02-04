
import { toArrayBuffer } from '../cbor'
import { SecretKeyJwk } from '../cose/sign1'

import subtleCryptoProvider from './subtleCryptoProvider'

import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

const signer = ({ secretKeyJwk }: { secretKeyJwk: SecretKeyJwk }) => {
  const digest = getDigestFromVerificationKey(`${secretKeyJwk.alg}`)
  return {
    sign: async (toBeSigned: ArrayBuffer): Promise<ArrayBuffer> => {
      const subtle = await subtleCryptoProvider()
      const signingKey = await subtle.importKey(
        "jwk",
        secretKeyJwk,
        {
          name: "ECDSA",
          namedCurve: secretKeyJwk.crv,
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