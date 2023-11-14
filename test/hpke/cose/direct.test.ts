import fs from 'fs'
import generate from '../jose/generate'
import direct from './direct'
import * as coseKey from '../../../src/key'
import alternateDiagnostic from '../../../src/diagnostic'

import { Suite0 } from '../common'

it('sanity', async () => {
  const k = await generate(Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const k2 = {
    cosePublicKey: coseKey.importJWK(k.publicKeyJwk),
    cosePrivateKey: coseKey.importJWK(k.privateKeyJwk)
  }
  const c3 = await direct.encrypt(m, k2.cosePublicKey)
  const c3Diagnostic = await alternateDiagnostic(c3)
  expect(c3Diagnostic.startsWith('96([')).toBe(true)
  const d3 = await direct.decrypt(c3, k2.cosePrivateKey)
  const rpt3 = new TextDecoder().decode(d3)
  expect(rpt3).toBe(pt)

  const markdown = `

# COSE HPKE Direct / 1 Layer

## Key

~~~~ cbor-diag
${await coseKey.beautify(k2.cosePrivateKey)}
~~~~

## Envelope

~~~~ cbor-diag
${c3Diagnostic.trim()}
~~~~
  
  `.trim()

  fs.writeFileSync('test/hpke/cose/direct.md', markdown)
})