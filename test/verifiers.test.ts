import fs from 'fs'

import * as cose from '../src'

it('verify multiple receipts', async () => {
  const issuerSecretKey = await cose.key.generate<cose.key.CoseKey>('ES256', 'application/cose-key')
  const notary1SecretKey = await cose.key.generate<cose.key.CoseKey>('ES256', 'application/cose-key')
  const notary2SecretKey = await cose.key.generate<cose.key.CoseKey>('ES256', 'application/cose-key')
  const issuerSigner = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(issuerSecretKey)
    })

  })
  const notary1Signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(notary1SecretKey)
    })

  })
  const notary2Signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.key.convertCoseKeyToJsonWebKey<cose.PrivateKeyJwk>(notary2SecretKey)
    })
  })
  const issuerCkt = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(issuerSecretKey)
  const notary1Ckt = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(notary1SecretKey)
  const notary2Ckt = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(notary2SecretKey)

  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuerSigner.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Kid, issuerCkt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.Protected.Alg, cose.Signature.ES256], // alg ES256
      [cose.Protected.ContentType, "image/png"], // content_type image/png
    ]),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await cose.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature1 = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Kid, notary1Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.Protected.Alg, cose.Signature.ES256],  // alg ES256
      [cose.Protected.VerifiableDataStructure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary1Signer
  })
  const receiptForImageSignature2 = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Kid, notary2Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.Protected.Alg, cose.Signature.ES256],  // alg ES256
      [cose.Protected.VerifiableDataStructure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary2Signer
  })
  const transparentSignature1 = await cose.receipt.add(signatureForImage, receiptForImageSignature1)
  const transparentSignature = await cose.receipt.add(transparentSignature1, receiptForImageSignature2)
  const resolve = async (coseSign1: cose.CoseSign1Bytes): Promise<cose.PublicKeyJwk> => {
    const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
    if (tag !== cose.COSE_Sign1) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
    const kid = protectedHeaderMap.get(cose.Protected.Kid);
    if (kid === issuerCkt) {
      return cose.key.convertCoseKeyToJsonWebKey(
        await cose.key.publicFromPrivate(issuerSecretKey)
      )
    }
    if (kid === notary1Ckt) {
      return cose.key.convertCoseKeyToJsonWebKey(
        await cose.key.publicFromPrivate(notary1SecretKey)
      )
    }
    if (kid === notary2Ckt) {
      return cose.key.convertCoseKeyToJsonWebKey(
        await cose.key.publicFromPrivate(notary2SecretKey)
      )
    }
    throw new Error('No verification key found in trust store.')
  }
  const verifier = await cose.receipt.verifier({
    resolve
  })
  const verified = await verifier.verify({ coseSign1: transparentSignature, payload: content })
  expect(verified.payload).toBeDefined()
  expect(verified.receipts.length).toBe(2)
})

