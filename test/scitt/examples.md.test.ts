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

it('issue receipt', async () => {
  lines.push(`## Issue Receipt`)
  const message0 = cose.cbor.encode(0)
  const message1 = cose.cbor.encode('1')
  const message2 = cose.cbor.encode([2, 2])
  const message3 = cose.cbor.encode({ 3: 3 })
  const message4 = cose.cbor.encode(['🔥', 4])
  const message5 = cose.cbor.encode({ five: '💀' })
  const entries = [message0, message1, message2, message3, message4, message5]
  const receipt = await cose.scitt.receipt.issue({
    index: 4,
    entries: entries,
    secretCoseKey
  })
  const diagnostic = await cose.scitt.receipt.edn(receipt)
  lines.push(`
\`\`\` ts
const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })
const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
const entries = [message0, message1, message2, message3, message4, message5]
const receipt = await cose.scitt.receipt.issue({
  index: 4,
  entries: entries,
  secretCoseKey
})
const diagnostic = await cose.scitt.receipt.edn(receipt)
\`\`\`
            `.trim())
  lines.push(diagnostic.trim())
})

afterAll(() => {
  const final = lines.join('\n\n')
  fs.writeFileSync('test/scitt/examples.md', final)
})
