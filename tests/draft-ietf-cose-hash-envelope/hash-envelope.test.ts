import fs from 'fs'
import * as cose from '../../src'

const key = fs.readFileSync('./tests/__fixtures__/cose-key.cbor')

it('cose key', async () => {
  const output = fs.readFileSync('./tests/__fixtures__/cose-key.diag')
  const diag = await cose.cbor.diag(key, "application/cose-key")
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
  fs.writeFileSync('./tests/draft-ietf-cose-hash-envelope/hash-envelope.cbor', signature)
  const input = fs.readFileSync('./tests/draft-ietf-cose-hash-envelope/hash-envelope.cbor')
  const diag = await cose.cbor.diag(input, "application/cose")
  fs.writeFileSync('./tests/draft-ietf-cose-hash-envelope/hash-envelope.diag', diag)
  const output = fs.readFileSync('./tests/draft-ietf-cose-hash-envelope/hash-envelope.diag')
  expect(diag).toBe(output.toString())
})
