import fs from 'fs'
import * as transmute from '../src'

it('sign and verify', async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.attached.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk
    })
  })
  const message = '💣 test ✨ mesage 🔥'
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload: new TextEncoder().encode(message)
  })
  // ... the network ...

  const verifier = transmute.attached.verifier({ publicKeyJwk })
  const verified = await verifier.verify({ coseSign1 })
  expect(new TextDecoder().decode(verified)).toBe(message)

  // fs.writeFileSync('./examples/attached.cose-sign1.cbor', Buffer.from(coseSign1))
})

it('sign and verify large image from file system', async () => {
  const secretKeyJwk = await transmute.key.generate<transmute.SecretKeyJwk>('ES256', 'application/jwk+json')
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicKeyJwk } = secretKeyJwk
  const signer = transmute.attached.signer({
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
  const verifier = transmute.attached.verifier({ publicKeyJwk })
  const verified = await verifier.verify({ coseSign1 })
  expect(Buffer.from(verified).toString('hex')).toEqual(content.toString('hex')) // faster to compare hex strings.
})