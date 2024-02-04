import fs from 'fs'
import * as cose from '../src'

it('readme', async () => {
  const issuerSecretKeyJwk = await cose.key.generate<cose.SecretKeyJwk>('ES256', 'application/jwk+json')
  const issuerPublicKeyJwk = await cose.key.publicFromPrivate<cose.PublicKeyJwk>(issuerSecretKeyJwk)

  const notarySecretKeyJwk = await cose.key.generate<cose.SecretKeyJwk>('ES256', 'application/jwk+json')
  const notaryPublicKeyJwk = await cose.key.publicFromPrivate<cose.PublicKeyJwk>(notarySecretKeyJwk)

  const issuer = cose.detached.signer({
    remote: cose.crypto.signer({
      secretKeyJwk: issuerSecretKeyJwk
    })
  })
  const notary = cose.detached.signer({
    remote: cose.crypto.signer({
      secretKeyJwk: notarySecretKeyJwk
    })
  })

  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuer.sign({
    protectedHeader: new Map<number, any>([
      [1, -7], // signing algorithm ES256
      [3, "image/png"], // content type image/png
      [4, issuerPublicKeyJwk.kid] // issuer key identifier
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [
    await cose.receipt.leaf(signatureForImage)
  ]
  const receiptForImageSignature = await cose.receipt.inclusion.issue({
    protectedHeader: new Map<number, any>([
      [1, -7],  // signing algorithm ES256
      [-111, 1], // inclusion proof from RFC9162
      [4, notaryPublicKeyJwk.kid] // notary key identifier
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary
  })
  const transparentSignature = await cose.receipt.add(signatureForImage, receiptForImageSignature)
  const resolve = async (header: cose.ProtectedHeaderMap): Promise<cose.PublicKeyJwk> => {
    const kid = header.get(4);
    if (kid === issuerPublicKeyJwk.kid) {
      return issuerPublicKeyJwk
    }
    if (kid === notaryPublicKeyJwk.kid) {
      return notaryPublicKeyJwk
    }
    throw new Error('No verification key found in trust store.')
  }
  const verifier = await cose.receipt.verifier({
    resolve
  })
  const verified = await verifier.verify({
    coseSign1: transparentSignature,
    payload: content
  })
  expect(verified.payload).toBeDefined()
  expect(verified.receipts.length).toBe(1)
})