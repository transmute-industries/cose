import fs from 'fs'

import * as transmute from '../src'

it('verify multiple receipts', async () => {
  const issuerSecretKey = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const notarySecretKey = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const issuerSigner = transmute.detached.signer({
    secretKeyJwk: await transmute.key.convertCoseKeyToJsonWebKey<transmute.SecretKeyJwk>(issuerSecretKey)
  })
  const notarySigner = transmute.detached.signer({
    secretKeyJwk: await transmute.key.convertCoseKeyToJsonWebKey<transmute.SecretKeyJwk>(notarySecretKey)
  })
  const issuerCkt = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(issuerSecretKey)
  const notaryCkt = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(notarySecretKey)
  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuerSigner.sign({
    protectedHeader: new Map<number, any>([
      [2, issuerCkt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [1, -7], // alg ES256
      [3, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await transmute.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map<number, any>([
      [2, notaryCkt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notarySigner
  })
  const transparentSignature = await transmute.receipt.add(signatureForImage, receiptForImageSignature)
  const resolve = async (header: transmute.ProtectedHeaderMap): Promise<transmute.PublicKeyJwk> => {
    throw new Error('No verification key found in trust store.')
  }
  const verifier = await transmute.receipt.verifier({
    resolve
  })
  const verified = await verifier.verify({ coseSign1: transparentSignature, payload: content })

})

