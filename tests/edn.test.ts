import fs from 'fs'
import * as cose from '../src'

const key = fs.readFileSync('./tests/__fixtures__/cose-key.cbor')
const encoder = new TextEncoder();

it('cose key', async () => {
  const output = fs.readFileSync('./tests/__fixtures__/cose-key.diag')
  const diag = await cose.cbor.diag(key, "application/cose-key")
  expect(diag).toBe(output.toString())
})

it('detached payload cose sign1', async () => {
  const input = fs.readFileSync('./tests/__fixtures__/detached-payload.cbor')
  const diag = await cose.cbor.diag(input, "application/cose")
  fs.writeFileSync('./tests/__fixtures__/detached-payload.diag', diag)
  const output = fs.readFileSync('./tests/__fixtures__/detached-payload.diag')
  expect(diag).toBe(output.toString())
})

it('hash envelope', async () => {
  const k = await cose.crypto.key.parse<'ES256', 'application/cose-key'>({
    key,
    type: 'application/cose-key'
  })
  const signer = await cose.crypto.key.signer({
    algorithm: 'ES256',
    key: k,
  })
  const signature = await cose.hash
    .signer({
      remote: signer
    })
    .sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.alg, cose.algorithm.es256],
        [cose.draft_headers.payload_hash_algorithm, cose.algorithm.sha_256],
        [cose.draft_headers.payload_preimage_content_type, 'application/spdx+json'],
        [cose.draft_headers.payload_location, 'https://s.example/sbom/42']
      ]),
      payload: Buffer.from('🔥 not a real sbom')
    })
  fs.writeFileSync('./tests/__fixtures__/hash-envelope.cbor', signature)
  const input = fs.readFileSync('./tests/__fixtures__/hash-envelope.cbor')
  const diag = await cose.cbor.diag(input, "application/cose")
  fs.writeFileSync('./tests/__fixtures__/hash-envelope.diag', diag)
  const output = fs.readFileSync('./tests/__fixtures__/hash-envelope.diag')
  expect(diag).toBe(output.toString())
})

it('cose receipt', async () => {
  const k = await cose.crypto.key.parse<'ES256', 'application/cose-key'>({
    key,
    type: 'application/cose-key'
  })
  const entries = await Promise.all([`💣 test`, `✨ test`, `🔥 test`]
    .map((entry) => {
      return encoder.encode(entry)
    })
    .map((entry) => {
      return cose.receipt.leaf(entry)
    }))
  const signer = await cose.sign1
    .signer({
      remote: await cose.crypto.key.signer({
        algorithm: 'ES256',
        key: k,
      })
    })
  const inclusion = await cose.receipt.inclusion.issue({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],
      [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256]
    ]),
    entry: 1,
    entries,
    signer
  })
  fs.writeFileSync('./tests/__fixtures__/inclusion.receipt.cbor', inclusion)
  const input = fs.readFileSync('./tests/__fixtures__/inclusion.receipt.cbor')
  const diag = await cose.cbor.diag(input, "application/cose")
  fs.writeFileSync('./tests/__fixtures__/inclusion.receipt.diag', diag)
})

