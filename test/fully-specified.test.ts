/* eslint-disable @typescript-eslint/no-unused-vars */
import fs from 'fs'
import * as cose from '../src'
const message = '💣 test ✨ mesage 🔥'


// https://datatracker.ietf.org/doc/draft-ietf-jose-fully-specified-algorithms/

it('sign and verify', async () => {
  const privateKeyJwk = await cose.key.generate<cose.PrivateKeyJwk>('ES256', 'application/jwk+json')
  const publicKeyJwk = await cose.key.extractPublicKeyJwk(privateKeyJwk)
  expect(new TextDecoder().decode(await cose.attached
    .verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })
    .verify({
      coseSign1: await cose.attached
        .signer({
          remote: cose.crypto.signer({
            privateKeyJwk
          })
        })
        .sign({
          protectedHeader: new Map([[1, -7]]),
          unprotectedHeader: new Map(),
          payload: new TextEncoder().encode(message)
        })
    }))).toBe(message)
})
