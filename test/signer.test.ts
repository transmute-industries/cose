import fs from 'fs'
import * as transmute from '../src'


it('sign and verify large image from file system', async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.detached.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk
    })
  })

  const content = fs.readFileSync('./examples/image.png')
  const coseSign1 = await signer.sign({
    protectedHeader: new Map<number, any>([
      [1, -7], // alg ES256
      [3, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })

  // ... the network ...
  const verifier = transmute.detached.verifier({
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