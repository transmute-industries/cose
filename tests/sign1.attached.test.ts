import fs from 'fs'
import * as cose from '../src'

import { JWK } from 'jose'

it('sign and verify', async () => {
  const privateKeyJwk = await cose.crypto.key.gen<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = privateKeyJwk
  const signer = cose.attached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const message = '💣 test ✨ mesage 🔥'
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[cose.header.alg, cose.algorithm.es256]]),
    unprotectedHeader: new Map(),
    payload: new TextEncoder().encode(message)
  })
  // ... the network ...

  const verifier = cose.attached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  })
  const verified = await verifier.verify({ coseSign1 })
  expect(new TextDecoder().decode(verified)).toBe(message)

  // fs.writeFileSync('./examples/attached.cose-sign1.cbor', Buffer.from(coseSign1))
})

it('sign and verify large image from file system', async () => {
  const privateKeyJwk = await cose.crypto.key.gen<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = privateKeyJwk
  const signer = cose.attached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })

  const content = fs.readFileSync('./examples/image.png')

  const coseSign1 = await signer.sign({
    protectedHeader: new Map<number, any>([
      [cose.header.alg, cose.algorithm.es256], // alg ES256
      [cose.header.content_type, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })

  // ... the network ...
  const verifier = cose.attached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk
      }
    }
  })
  const verified = await verifier.verify({ coseSign1 })
  expect(Buffer.from(verified).toString('hex')).toEqual(content.toString('hex')) // faster to compare hex strings.
})