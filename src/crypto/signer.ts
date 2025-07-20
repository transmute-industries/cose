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

            let signingKey: CryptoKey
            let algorithmParams: any

            // Determine algorithm type and parameters
            if (alg?.startsWith('ES')) {
                // ECDSA algorithms
                signingKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "ECDSA",
                        namedCurve: withoutAlg.crv,
                    },
                    true,
                    ["sign"],
                )
                algorithmParams = {
                    name: "ECDSA",
                    hash: { name: digest },
                }
            } else if (alg?.startsWith('PS')) {
                // RSA-PSS algorithms (RFC 8230)
                signingKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "RSA-PSS",
                        hash: digest,
                    },
                    true,
                    ["sign"],
                )

                // Determine salt length based on hash algorithm (RFC 8230)
                const saltLength = digest === 'SHA-256' ? 32 : digest === 'SHA-384' ? 48 : 64

                algorithmParams = {
                    name: "RSA-PSS",
                    saltLength: saltLength,
                }
            } else if (alg?.startsWith('RS')) {
                // RSA-PKCS1 algorithms (if needed in the future)
                signingKey = await subtle.importKey(
                    "jwk",
                    withoutAlg,
                    {
                        name: "RSASSA-PKCS1-v1_5",
                        hash: digest,
                    },
                    true,
                    ["sign"],
                )
                algorithmParams = {
                    name: "RSASSA-PKCS1-v1_5",
                }
            } else {
                throw new Error(`Unsupported algorithm: ${alg}`)
            }

            const signature = await subtle.sign(
                algorithmParams,
                signingKey,
                toBeSigned,
            );

            return new Uint8Array(signature);
        }
    }
}

export default signer