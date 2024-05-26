import * as cose from '../../src'

it('ML-DSA-65', async () => {
  const secretKey = await cose.key.generate<cose.key.CoseKey>('ML-DSA-65')
  const publicKey = await cose.key.publicFromPrivate<cose.key.CoseKey>(secretKey)
  const signer = cose.detached.signer({
    remote: cose.key.signer(secretKey)
  })
  const message = '💣 test ✨ mesage 🔥'
  const payload = new TextEncoder().encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([
      [1, -49] // alg : ML-DSA-65
    ]),
    unprotectedHeader: new Map(),
    payload
  })
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return cose.key.convertCoseKeyToJsonWebKey(publicKey)
      }
    }
  })
  // console.log(await cose.cbor.diagnose(coseSign1))
  const verified = await verifier.verify({ coseSign1, payload: payload })
  expect(new TextDecoder().decode(verified)).toBe(message)
})