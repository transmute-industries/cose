

import { JWK } from 'jose'

import getDigestFromVerificationKey from '../cose/sign1/getDigestFromVerificationKey'

import subtleCryptoProvider from './subtle'

const verifier = ({ publicKeyJwk }: { publicKeyJwk: JWK }) => {
  const digest = getDigestFromVerificationKey(`${publicKeyJwk.alg}`)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { alg, ...withoutAlg } = publicKeyJwk
  return {
    verify: async (toBeSigned: Uint8Array, signature: Uint8Array): Promise<Uint8Array> => {
      const subtle = await subtleCryptoProvider()
      const verificationKey = await subtle.importKey(
        "jwk",
        withoutAlg,
        {
          name: "ECDSA",
          namedCurve: withoutAlg.crv,
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