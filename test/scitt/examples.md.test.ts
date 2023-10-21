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
let publicCoseKey: any
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
  publicCoseKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
  const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicCoseKey)
  const diagnosticOfPublicKey = await cose.key.edn(publicCoseKey)
  lines.push(`
\`\`\` ts
const publicCoseKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicCoseKey)
const diagnosticOfPublicKey = await cose.key.edn(publicCoseKey)
\`\`\`
            `.trim())
  lines.push(`
~~~~ text
${thumbprintOfPublicKey}
~~~~
                `.trim())
  lines.push(makeRfcCodeBlock(diagnosticOfPublicKey))
})

const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })
const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
const entries = [message0, message1, message2, message3, message4, message5]

let receipt: ArrayBuffer
it('issue receipt', async () => {
  lines.push(`## Issue Receipt`)
  receipt = await cose.scitt.receipt.issue({
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

it('verify receipt', async () => {
  lines.push(`## Verify Receipt`)
  const verificaton = await cose.scitt.receipt.verify({
    entry: entries[4],
    receipt,
    publicCoseKey
  })
  expect(verificaton).toBe(true)
  lines.push(`
\`\`\` ts
const verificaton = await cose.scitt.receipt.verify({
  entry: entries[4],
  receipt,
  publicCoseKey
})
console.log({ verificaton })
\`\`\`
            `.trim())
  lines.push(`
~~~~ text
{ verificaton: true }
~~~~`)
})

afterAll(() => {
  const final = lines.join('\n\n')
  fs.writeFileSync('test/scitt/examples.md', final)
})
