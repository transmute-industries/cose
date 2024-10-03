/* eslint-disable @typescript-eslint/no-unused-vars */
import { JWK } from 'jose'

import subtleCryptoProvider from './subtle'

import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

const signer = ({ privateKeyJwk }: { privateKeyJwk: JWK | any }) => {
  const digest = getDigestFromVerificationKey(`${privateKeyJwk.alg}`)
  const { alg, ...withoutAlg } = privateKeyJwk
  return {
    sign: async (toBeSigned: Uint8Array): Promise<Uint8Array> => {
      const subtle = await subtleCryptoProvider()
      const signingKey = await subtle.importKey(
        "jwk",
        withoutAlg,
        {
          name: "ECDSA",
          namedCurve: withoutAlg.crv,
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

      return new Uint8Array(signature);
    }
  }
}

export default signer