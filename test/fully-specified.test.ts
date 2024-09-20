
import * as cose from '../src'
import { CoseSignatureAlgorithms } from '../src/cose/key'

const message = '💣 test ✨ mesage 🔥'

const helpTestSignAndVerify = async (privateKey: cose.key.CoseKey) => {
  const publicKey = await cose.key.extractPublicCoseKey(privateKey)
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
            [cose.Protected.Alg, privateKey.get(cose.Key.Alg)]
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
    const privateKey = await cose.key.generate<cose.key.CoseKey>(alg, 'application/cose-key')
    await helpTestSignAndVerify(privateKey)
  })
})


