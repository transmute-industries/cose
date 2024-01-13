import fs from 'fs'
import generate from '../jose/generate'
import wrap from './wrap'
import * as coseKey from '../../../src/key'
import { Suite0 } from '../common'
import alternateDiagnostic from '../../../src/diagnostic'
import cbor from '../../../src/cbor'

it.skip('sanity', async () => {
  const k = await generate(Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const k2 = {
    cosePublicKey: coseKey.importJWK(k.publicKeyJwk),
    cosePrivateKey: coseKey.importJWK(k.privateKeyJwk)
  }
  const c4 = await wrap.encrypt(m, k2.cosePublicKey)

  const decoded = await cbor.decode(c4)
  const dL0Protected = await alternateDiagnostic(decoded.value[0])
  // console.log(dL0Protected)
  expect(dL0Protected).toBe(`{
1: 1
}
`)
  const dL1Protected = await alternateDiagnostic(decoded.value[3][0][0])
  // console.log(dL1Protected)
  expect(dL1Protected).toBe(`{
1: -55555
}
`)
  const c4Diagnostic = await alternateDiagnostic(c4)
  // console.log('/ COSE HPKE Wrap /\n' + c4Diagnostic)
  expect(c4Diagnostic.startsWith('96([')).toBe(true)
  const d4 = await wrap.decrypt(c4, k2.cosePrivateKey)
  const rpt4 = new TextDecoder().decode(d4)
  expect(rpt4).toBe(pt)

  const markdown = `

# COSE HPKE Wrap / 2 Layer

## Key

~~~~ cbor-diag
${await coseKey.beautify(k2.cosePrivateKey)}
~~~~

## Envelope

~~~~ cbor-diag
${c4Diagnostic.trim()}
~~~~
  
  `.trim()

  fs.writeFileSync('test/hpke/cose/wrap.md', markdown)
})