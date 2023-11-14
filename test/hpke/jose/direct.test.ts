import fs from 'fs'

import { Suite0 } from '../common'
import generate from './generate'
import direct from './direct'


it('sanity', async () => {
  const k = await generate(Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const c = await direct.encrypt(m, k.publicKeyJwk)
  const d = await direct.decrypt(c, k.privateKeyJwk)
  const rpt = new TextDecoder().decode(d)
  expect(rpt).toBe(pt)

  const markdown = `

# JOSE HPKE Direct / 1 Layer

## Key

~~~~ json
${JSON.stringify(k.privateKeyJwk, null, 2)}
~~~~

## Envelope

~~~~ json
${JSON.stringify(c, null, 2)}
~~~~
  
  `.trim()

  fs.writeFileSync('test/hpke/jose/direct.md', markdown)

})