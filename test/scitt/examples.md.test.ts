import fs from 'fs'
import cose from '../../src'
import { makeRfcCodeBlock } from '../../src/rfc/beautify/makeRfcCodeBlock'

const lines = [] as string[]
lines.push(`
\`\`\` ts
import cose from '@transmute/cose'
\`\`\`
          `.trim())

let secretCoseKey: any
it('generate private key', async () => {
  lines.push(`## Generate Private Key`)
  secretCoseKey = await cose.key.generate(-7)
  const thumbprintOfSecretKey = await cose.key.thumbprint.uri(secretCoseKey)
  const diagnosticOfSecretKey = await cose.key.edn(secretCoseKey)
  lines.push(`
\`\`\` ts
const secretCoseKey = await cose.key.generate(-7)
const thumbprintOfSecretKey = await cose.key.thumbprint.uri(secretCoseKey)
const diagnosticOfSecretKey = await cose.key.edn(secretCoseKey)
\`\`\`
            `.trim())

  lines.push(`
~~~~ text
${thumbprintOfSecretKey}
~~~~
    `.trim())
  lines.push(makeRfcCodeBlock(diagnosticOfSecretKey))


})

it('export public key', async () => {

  lines.push(`## Export Public Key`)
  const publicKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
  const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicKey)
  const diagnosticOfPublicKey = await cose.key.edn(publicKey)
  lines.push(`
\`\`\` ts
const publicKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicKey)
const diagnosticOfPublicKey = await cose.key.edn(publicKey)
\`\`\`
            `.trim())
  lines.push(`
~~~~ text
${thumbprintOfPublicKey}
~~~~
                `.trim())
  lines.push(makeRfcCodeBlock(diagnosticOfPublicKey))

})


afterAll(() => {
  const final = lines.join('\n\n')
  fs.writeFileSync('test/scitt/examples.md', final)
})
