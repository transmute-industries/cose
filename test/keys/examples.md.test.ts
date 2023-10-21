import fs from 'fs'
import cose from '../../src'
import { makeRfcCodeBlock } from '../../src/rfc/beautify/makeRfcCodeBlock'

it('can generate markdown examples', async () => {
  const lines = [] as string[]
  lines.push(`
\`\`\` ts
import cose from '@transmute/cose'
\`\`\`
          `.trim())
  const algorithms = ['ES256', 'ES384', 'ES512']
  for (const jwa of algorithms) {
    lines.push(`## ${jwa}`)

    const coseAlg = cose.key.utils.algorithms.toCOSE.get(jwa) as number
    const coseKey = await cose.key.generate(coseAlg)
    lines.push(`
\`\`\` ts
const coseKey = await cose.key.generate(${coseAlg})
\`\`\`
            `.trim())
    const asJwk = cose.key.exportJWK(coseKey) as any
    const coseKeyEdn = await cose.key.beautify(coseKey)
    lines.push(`### EDN`)
    lines.push(`
\`\`\` ts
const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey)
\`\`\`
      `.trim())
    const coseKeyThumbprintUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(coseKey)
    lines.push(`
~~~~ text
${coseKeyThumbprintUri}
~~~~
    `.trim())
    lines.push(makeRfcCodeBlock(coseKeyEdn))
    lines.push(`### JSON`)
    lines.push(`
\`\`\` ts
const jwk = await cose.key.exportJWK(coseKey)
\`\`\`
        `.trim())
    const coseKeyAsJwkThumbprintUri = await cose.key.thumbprint.calculateJwkThumbprintUri(asJwk)
    lines.push(`
    \`\`\` ts
const jktUri = await cose.key.thumbprint.calculateJwkThumbprintUri(jwk)
    \`\`\`
          `.trim())
    lines.push(`
~~~~ text
${coseKeyAsJwkThumbprintUri}
~~~~
    `.trim())
    const coseKeyAsJwk = JSON.stringify(asJwk, null, 2)
    lines.push(`
~~~~ json
${coseKeyAsJwk}
~~~~
    `.trim())
  }

  const final = lines.join('\n\n')
  fs.writeFileSync('test/keys/examples.md', final)
})
