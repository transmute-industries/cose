import fs from 'fs'
import { JWK } from 'jose'
import * as cose from '../src'

it('readme', async () => {
  const issuerSecretKeyJwk = await cose.key.generate<JWK>('ES256', 'application/jwk+json')
  const issuerPublicKeyJwk = await cose.key.publicFromPrivate<JWK>(issuerSecretKeyJwk)

  const notarySecretKeyJwk = await cose.key.generate<JWK>('ES256', 'application/jwk+json')
  const notaryPublicKeyJwk = await cose.key.publicFromPrivate<JWK>(notarySecretKeyJwk)

  const issuer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: issuerSecretKeyJwk
    })
  })
  const notary = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: notarySecretKeyJwk
    })
  })
  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256], // signing algorithm ES256
      [cose.header.content_type, "image/png"], // content type image/png
      [cose.header.kid, issuerPublicKeyJwk.kid] // issuer key identifier
    ]),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [
    await cose.receipt.leaf(signatureForImage)
  ]
  const receiptForImageSignature = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']],
      [cose.header.kid, notaryPublicKeyJwk.kid]
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary
  })
  const transparentSignature = await cose.receipt.add(signatureForImage, receiptForImageSignature)
  const resolve = async (coseSign1: cose.CoseSign1Bytes): Promise<JWK> => {
    const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
    if (tag !== cose.tag.COSE_Sign1) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
    const kid = protectedHeaderMap.get(cose.header.kid);
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