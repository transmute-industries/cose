import fs from 'fs'
import * as cose from '../src'

it('sign and verify', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = privateKeyJwk
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const message = '💣 test ✨ mesage 🔥'
  const payload = new TextEncoder().encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Signature.ES256], // alg ES256
    ]),
    payload
  })
  const { tag, value } = await cose.cbor.decode(coseSign1)
  expect(tag).toBe(18) // cose sign 1
  expect(value[2]).toBe(null) // detached payload

  // ... the network ...
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  })
  const verified = await verifier.verify({ coseSign1, payload })
  expect(new TextDecoder().decode(verified)).toBe(message)

  // fs.writeFileSync('./examples/detached.cose-sign1.cbor', Buffer.from(coseSign1))
})

it('sign and verify large image from file system', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = privateKeyJwk
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const content = fs.readFileSync('./examples/image.png')
  const coseSign1 = await signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Signature.ES256], // alg ES256
      [cose.Protected.ContentType, "image/png"], // content_type image/png
    ]),
    payload: content
  })

  // ... the network ...
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  })
  const verified = await verifier.verify({ coseSign1, payload: content })
  // faster to compare hex strings.
  expect(Buffer.from(verified).toString('hex')).toEqual(content.toString('hex'))

})