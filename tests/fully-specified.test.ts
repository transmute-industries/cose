
import * as cose from '../src'
import { CoseSignatureAlgorithms } from '../src/cose/key'

const message = '💣 test ✨ mesage 🔥'

const helpTestSignAndVerify = async (privateKey: cose.any_cose_key) => {
  const publicKey = await cose.key.extractPublicCoseKey<cose.any_cose_key>(privateKey)
  expect(new TextDecoder().decode(await cose.attached
    .verifier({
      resolver: {
        resolve: async () => {
          return cose.key.convertCoseKeyToJsonWebKey(publicKey)
        }
      }
    })
    .verify({
      coseSign1: await cose.attached
        .signer({
          remote: cose.crypto.signer({
            privateKeyJwk: await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(privateKey)
          })
        })
        .sign({
          protectedHeader: new Map([
            [cose.header.alg, privateKey.get(cose.cose_key.alg)]
          ]),
          payload: new TextEncoder().encode(message)
        })
    }))).toBe(message)
}

// https://datatracker.ietf.org/doc/draft-ietf-jose-fully-specified-algorithms/

const algorithms = [
  "ESP256",
  "ESP384"
] as CoseSignatureAlgorithms[]

algorithms.forEach((alg) => {
  it(alg, async () => {
    const privateKey = await cose.key.generate<cose.ec2_key>(alg, 'application/cose-key')
    await helpTestSignAndVerify(privateKey)
  })
})


