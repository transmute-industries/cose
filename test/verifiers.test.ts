import fs from 'fs'

import * as transmute from '../src'

it('verify multiple receipts', async () => {
  const issuerSecretKey = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const notary1SecretKey = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const notary2SecretKey = await transmute.key.generate<transmute.key.CoseKey>('ES256', 'application/cose-key')
  const issuerSigner = transmute.detached.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk: await transmute.key.convertCoseKeyToJsonWebKey<transmute.SecretKeyJwk>(issuerSecretKey)
    })

  })
  const notary1Signer = transmute.detached.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk: await transmute.key.convertCoseKeyToJsonWebKey<transmute.SecretKeyJwk>(notary1SecretKey)
    })

  })
  const notary2Signer = transmute.detached.signer({
    remote: transmute.crypto.signer({
      secretKeyJwk: await transmute.key.convertCoseKeyToJsonWebKey<transmute.SecretKeyJwk>(notary2SecretKey)
    })
  })
  const issuerCkt = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(issuerSecretKey)
  const notary1Ckt = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(notary1SecretKey)
  const notary2Ckt = await transmute.key.thumbprint.calculateCoseKeyThumbprintUri(notary2SecretKey)

  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuerSigner.sign({
    protectedHeader: new Map<number, any>([
      [4, issuerCkt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [1, -7], // alg ES256
      [3, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await transmute.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature1 = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map<number, any>([
      [4, notary1Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary1Signer
  })
  const receiptForImageSignature2 = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map<number, any>([
      [4, notary2Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary2Signer
  })
  const transparentSignature1 = await transmute.receipt.add(signatureForImage, receiptForImageSignature1)
  const transparentSignature = await transmute.receipt.add(transparentSignature1, receiptForImageSignature2)
  const resolve = async (coseSign1: transmute.CoseSign1Bytes): Promise<transmute.PublicKeyJwk> => {
    const { tag, value } = transmute.cbor.decodeFirstSync(coseSign1)
    if (tag !== 18) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = transmute.cbor.decodeFirstSync(protectedHeaderBytes)
    const kid = protectedHeaderMap.get(4);
    if (kid === issuerCkt) {
      return transmute.key.convertCoseKeyToJsonWebKey(
        await transmute.key.publicFromPrivate(issuerSecretKey)
      )
    }
    if (kid === notary1Ckt) {
      return transmute.key.convertCoseKeyToJsonWebKey(
        await transmute.key.publicFromPrivate(notary1SecretKey)
      )
    }
    if (kid === notary2Ckt) {
      return transmute.key.convertCoseKeyToJsonWebKey(
        await transmute.key.publicFromPrivate(notary2SecretKey)
      )
    }
    throw new Error('No verification key found in trust store.')
  }
  const verifier = await transmute.receipt.verifier({
    resolve
  })
  const verified = await verifier.verify({ coseSign1: transparentSignature, payload: content })
  expect(verified.payload).toBeDefined()
  expect(verified.receipts.length).toBe(2)
})

