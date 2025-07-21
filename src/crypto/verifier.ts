

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

            let verificationKey: CryptoKey
            let algorithmParams: any

            // Determine algorithm type and parameters
            if (alg?.startsWith('ES')) {
                // ECDSA algorithms
                verificationKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "ECDSA",
                        namedCurve: withoutAlg.crv,
                    },
                    true,
                    ["verify"],
                )
                algorithmParams = {
                    name: "ECDSA",
                    hash: { name: digest },
                }
            } else if (alg?.startsWith('PS')) {
                // RSA-PSS algorithms (RFC 8230)
                verificationKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "RSA-PSS",
                        hash: digest,
                    },
                    true,
                    ["verify"],
                )

                // Determine salt length based on hash algorithm (RFC 8230)
                const saltLength = digest === 'SHA-256' ? 32 : digest === 'SHA-384' ? 48 : 64

                algorithmParams = {
                    name: "RSA-PSS",
                    saltLength: saltLength,
                }
            } else if (alg?.startsWith('RS')) {
                // RSA-PKCS1 algorithms (if needed in the future)
                verificationKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: digest,
                    },
                    true,
                    ["verify"],
                )
                algorithmParams = {
                    name: "RSASSA-PKCS1-v1_5",
                }
            } else {
                throw new Error(`Unsupported algorithm: ${alg}`)
            }

            const verified = await subtle.verify(
                algorithmParams,
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