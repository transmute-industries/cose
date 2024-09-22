import fs from 'fs'
import * as cose from '../src'

it('cose key', async () => {
  const input = fs.readFileSync('./tests/__fixtures__/cose-key.cbor')
  const output = fs.readFileSync('./tests/__fixtures__/cose-key.diag')
  const diag = await cose.cbor.diag(input, "application/cose-key")
  expect(diag).toBe(output.toString())
})


it('detached payload cose sign1', async () => {
  const input = fs.readFileSync('./tests/__fixtures__/detached-payload.cbor')
  // const output = fs.readFileSync('./tests/__fixtures__/detached-payload.diag')
  const diag = await cose.cbor.diag(input, "application/cose")
  // console.log(diag)
  // expect(diag).toBe(output.toString())
})

// Tomorrow...
// More EDN examples for SCITT stuff
// maybe HPKE...