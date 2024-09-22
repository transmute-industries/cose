import fs from 'fs'

import * as cose from '../src'

import { JWK } from 'jose'

it('verify multiple receipts', async () => {

  const issuerSecretKey = await cose.crypto.key.gen<'ES256', 'application/cose-key'>({
    type: "application/cose-key",
    algorithm: "ES256"
  })
  const notary1SecretKey = await cose.crypto.key.gen<'ES256', 'application/cose-key'>({
    type: "application/cose-key",
    algorithm: "ES256"
  })
  const notary2SecretKey = await cose.crypto.key.gen<'ES256', 'application/cose-key'>({
    type: "application/cose-key",
    algorithm: "ES256"
  })

  const issuerSigner = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.crypto.key.cose_key_to_web_key<JWK>(issuerSecretKey)
    })

  })
  const notary1Signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.crypto.key.cose_key_to_web_key<JWK>(notary1SecretKey)
    })

  })
  const notary2Signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.crypto.key.cose_key_to_web_key<JWK>(notary2SecretKey)
    })
  })
  const issuerCkt = await cose.crypto.key.cose_key_thumbprint_uri(issuerSecretKey)
  const notary1Ckt = await cose.crypto.key.cose_key_thumbprint_uri(notary1SecretKey)
  const notary2Ckt = await cose.crypto.key.cose_key_thumbprint_uri(notary2SecretKey)

  const content = fs.readFileSync('./examples/image.png')
  const signatureForImage = await issuerSigner.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.kid, issuerCkt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.header.alg, cose.algorithm.es256], // alg ES256
      [cose.header.content_type, "image/png"], // content_type image/png
    ]),
    payload: content
  })
  const transparencyLogContainingImageSignatures = [await cose.receipt.leaf(signatureForImage)]
  // inclusion proof receipt for image signature
  const receiptForImageSignature1 = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.kid, notary1Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary1Signer
  })
  const receiptForImageSignature2 = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.kid, notary2Ckt], // kid urn:ietf:params:oauth:ckt:sha-256:T6ixLT_utMNJ...
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.draft_headers.verifiable_data_structure, cose.VerifiableDataStructures['RFC9162-Binary-Merkle-Tree']] // vds RFC9162
    ]),
    entry: 0,
    entries: transparencyLogContainingImageSignatures,
    signer: notary2Signer
  })
  const transparentSignature1 = await cose.receipt.add(signatureForImage, receiptForImageSignature1)
  const transparentSignature = await cose.receipt.add(transparentSignature1, receiptForImageSignature2)
  const resolve = async (coseSign1: cose.CoseSign1Bytes): Promise<cose.PublicKeyJwk> => {
    const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
    if (tag !== cose.tag.COSE_Sign1) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
    const kid = protectedHeaderMap.get(cose.header.kid);
    if (kid === issuerCkt) {
      return cose.crypto.key.cose_key_to_web_key(
        await cose.crypto.key.public_from_private<'ES256', 'application/cose-key'>({
          key: issuerSecretKey,
          type: 'application/cose-key'
        })
      )
    }
    if (kid === notary1Ckt) {
      return cose.crypto.key.cose_key_to_web_key(
        await cose.crypto.key.public_from_private<'ES256', 'application/cose-key'>({
          key: notary1SecretKey,
          type: 'application/cose-key'
        })
      )
    }
    if (kid === notary2Ckt) {
      return cose.crypto.key.cose_key_to_web_key(
        await cose.crypto.key.public_from_private<'ES256', 'application/cose-key'>({
          key: notary2SecretKey,
          type: 'application/cose-key'
        })
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

