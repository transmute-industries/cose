import fs from 'fs'
import * as cose from '../src'

const key = fs.readFileSync('./tests/__fixtures__/cose-key.cbor')

it('cose key', async () => {
  const output = fs.readFileSync('./tests/__fixtures__/cose-key.diag')
  const diag = await cose.cbor.diag(key, "application/cose-key")
  expect(diag).toBe(output.toString())
})

it('detached payload cose sign1', async () => {
  const input = fs.readFileSync('./tests/__fixtures__/detached-payload.cbor')
  const output = fs.readFileSync('./tests/__fixtures__/detached-payload.diag')
  const diag = await cose.cbor.diag(input, "application/cose")
  expect(diag).toBe(output.toString())
})

it.skip('hash envelope', async () => {
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
        [cose.draft_headers.payload_hash_algorithm, cose.algorithm.sha_256]
      ]),
      payload: Buffer.from('hello')
    })

  console.log(signature)
})

