/* eslint-disable @typescript-eslint/no-unused-vars */
import { JWK } from 'jose'

import { toArrayBuffer } from '../cbor'
import { PrivateKeyJwk } from '../cose/sign1'

import subtleCryptoProvider from './subtleCryptoProvider'

import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

const signer = ({ privateKeyJwk }: { privateKeyJwk: JWK }) => {
  const digest = getDigestFromVerificationKey(`${privateKeyJwk.alg}`)
  const { alg, ...withoutAlg } = privateKeyJwk
  return {
    sign: async (toBeSigned: ArrayBuffer): Promise<ArrayBuffer> => {
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

      return toArrayBuffer(signature);
    }
  }
}

export default signer