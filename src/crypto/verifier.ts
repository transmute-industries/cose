



import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

import subtleCryptoProvider from './subtleCryptoProvider'
import { PublicKeyJwk } from '../cose/sign1'

const verifier = ({ publicKeyJwk }: { publicKeyJwk: PublicKeyJwk }) => {
  const digest = getDigestFromVerificationKey(`${publicKeyJwk.alg}`)
  return {
    verify: async (toBeSigned: ArrayBuffer, signature: ArrayBuffer): Promise<ArrayBuffer> => {
      const subtle = await subtleCryptoProvider()
      const verificationKey = await subtle.importKey(
        "jwk",
        publicKeyJwk,
        {
          name: "ECDSA",
          namedCurve: publicKeyJwk.crv,
        },
        true,
        ["verify"],
      )
      const verified = await subtle.verify(
        {
          name: "ECDSA",
          hash: { name: digest },
        },
        verificationKey,
        signature,
        toBeSigned,
      );
      if (!verified) {
        throw new Error('Signature verification failed');
      }
      return toBeSigned;
    }
  }
}

export default verifier