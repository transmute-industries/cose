import fs from 'fs'
import * as cose from '../src'

import { JWK } from 'jose'

it('sign and verify large image from file system', async () => {
  const privateKeyJwk = await cose.key.generate<JWK>('ES256', 'application/jwk+json')
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
      [cose.header.alg, cose.algorithm.es256], // alg ES256
      [cose.header.content_type, "image/png"], // content_type image/png
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