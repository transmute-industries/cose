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

const statement = Buffer.from(JSON.stringify({
  "spdxVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "sbom-tool v0.1.2",
  "documentNamespace": "https://sbom.microsoft/sbom-tool/v0.1.2/sxs6e--NIEC8xIJRVxEbQQ",
  "creationInfo": {
    "created": "2022-07-05T22:11:05Z",
    "creators": [
      "Organization: Microsoft",
      "Tool: Microsoft.SBOMTool-0.0.0-alpha.0.13\u002Bbuild.37"
    ]
  },
  "documentDescribes": [
    "SPDXRef-RootPackage"
  ],
  "files": [
    {
      "fileName": "./sbom-tool-win-x64.exe",
      "SPDXID": "SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5"
        }
      ],
      "licenseConcluded": "NOASSERTION",
      "licenseInfoInFiles": [
        "NOASSERTION"
      ],
      "copyrightText": "NOASSERTION"
    }
  ],
  "packages": [
    {
      "name": "NuGet.Packaging",
      "SPDXID": "SPDXRef-Package-F374B589EF5A916D768BC9BDD592C16C2436F9F20F975BCF9458F1FFB2E91504",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseInfoFromFiles": [
        "NOASSERTION"
      ],
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "versionInfo": "5.6.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:nuget/NuGet.Packaging%405.6.0"
        }
      ],
      "supplier": "NOASSERTION"
    },
  ],
  "externalDocumentRefs": [],
  "relationships": [
    {
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-RootPackage",
      "spdxElementId": "SPDXRef-DOCUMENT"
    },
    {
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6",
      "spdxElementId": "SPDXRef-RootPackage"
    },
  ]
}))

let signedStatement: ArrayBuffer
it('issue statement', async () => {
  signedStatement = await cose.scitt.statement.issue({
    iss: 'software.vendor.example',
    sub: 'vendor.product.example',
    cty: 'application/spdx+json',
    secretCoseKey,
    payload: statement
  })
  entries.push(Buffer.from(signedStatement))
  lines.push(`## Issue Statement`)
  const diagnostic = await cose.scitt.receipt.edn(signedStatement)
  lines.push(`
\`\`\` ts
const statement = Buffer.from(JSON.stringify({
  "spdxVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "sbom-tool v0.1.2",
  "documentNamespace": "https://sbom.microsoft/sbom-tool/v0.1.2/sxs6e--NIEC8xIJRVxEbQQ",
  "creationInfo": {
    "created": "2022-07-05T22:11:05Z",
    "creators": [
      "Organization: Microsoft",
      "Tool: Microsoft.SBOMTool-0.0.0-alpha.0.13\u002Bbuild.37"
    ]
  },
  "documentDescribes": [
    "SPDXRef-RootPackage"
  ],
  "files": [
    {
      "fileName": "./sbom-tool-win-x64.exe",
      "SPDXID": "SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5"
        }
      ],
      "licenseConcluded": "NOASSERTION",
      "licenseInfoInFiles": [
        "NOASSERTION"
      ],
      "copyrightText": "NOASSERTION"
    }
  ],
  "packages": [
    {
      "name": "NuGet.Packaging",
      "SPDXID": "SPDXRef-Package-F374B589EF5A916D768BC9BDD592C16C2436F9F20F975BCF9458F1FFB2E91504",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseInfoFromFiles": [
        "NOASSERTION"
      ],
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "versionInfo": "5.6.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:nuget/NuGet.Packaging%405.6.0"
        }
      ],
      "supplier": "NOASSERTION"
    },
  ],
  "externalDocumentRefs": [],
  "relationships": [
    {
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-RootPackage",
      "spdxElementId": "SPDXRef-DOCUMENT"
    },
    {
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6",
      "spdxElementId": "SPDXRef-RootPackage"
    },
  ]
}))
const signedStatement = await cose.scitt.statement.issue({
  iss: 'software.vendor.example',
  sub: 'vendor.product.example',
  cty: 'application/spdx+json',
  secretCoseKey,
  payload: statement
})
const diagnostic = await cose.scitt.receipt.edn(receipt)
\`\`\`
            `.trim())
  lines.push(diagnostic.trim())
})


it('verify signed statement', async () => {
  const verificaton = await cose.scitt.statement.verify({
    statement,
    signedStatement,
    publicCoseKey
  })
  expect(verificaton).toBe(true)
  lines.push(`## Verify Signed Statement`)
  lines.push(`
\`\`\` ts
const verificaton = await cose.scitt.statement.verify({
  statement,
  signedStatement,
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

let receipt: ArrayBuffer
it('issue receipt', async () => {
  lines.push(`## Issue Receipt`)
  entries.push(Buffer.from(signedStatement))
  const logIndex = entries.length - 1 // last entry is the signed statement
  receipt = await cose.scitt.receipt.issue({
    iss: 'transparency.vendor.example',
    sub: 'vendor.product.example',
    index: logIndex,
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
entries.push(Buffer.from(signedStatement))
const logIndex = entries.length - 1 // last entry is the signed statement
receipt = await cose.scitt.receipt.issue({
  index: logIndex,
  entries: entries,
  secretCoseKey
})
const diagnostic = await cose.scitt.receipt.edn(receipt)
\`\`\`
            `.trim())
  lines.push(diagnostic.trim())
})

it('verify receipt', async () => {
  const logIndex = entries.length - 1 // last entry is the signed statement
  lines.push(`## Verify Receipt`)
  const verificaton = await cose.scitt.receipt.verify({
    entry: entries[logIndex],
    receipt,
    publicCoseKey
  })
  expect(verificaton).toBe(true)
  lines.push(`
\`\`\` ts
const logIndex = entries.length - 1 // last entry is the signed statement
const verificaton = await cose.scitt.receipt.verify({
  entry: entries[logIndex],
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

it('compose transparent statement', async () => {
  lines.push(`## Transparent Statement`)
  const transparentStatement = cose.scitt.statement.addReceipt({
    statement: signedStatement,
    receipt
  })

  const { entry, receipts } = cose.scitt.statement.getEntryReceipts({ transparentStatement })
  expect(entry).toBeDefined()
  expect(receipts.length).toBe(1)
  lines.push(`
\`\`\` ts
const transparentStatement = await cose.scitt.statement.addReceipt({
  statement: signedStatement,
  receipt
})
const { entry, receipts } = cose.scitt.statement.getEntryReceipts({ transparentStatement })
\`\`\`
            `.trim())
  const diagnostic = await cose.scitt.receipt.edn(transparentStatement)
  // fs.writeFileSync('test/scitt/ts.cose', transparentStatement)
  lines.push(diagnostic.trim())
})

it('x5c example', async () => {
  const publicKeyCose = cose.cbor.decode(fs.readFileSync('test/keys/x.509.user.publicKey.cose'))
  const privateKeyCose = cose.cbor.decode(fs.readFileSync('test/keys/x.509.user.privateKey.cose'))
  const statement = Buffer.from(JSON.stringify({ "hello": 'world' }))
  const signature = await cose.scitt.statement.issue({
    iss: 'urn:example:123',
    sub: 'urn:example:456',
    cty: 'application/json',
    x5c: publicKeyCose.get(-66666), // there is no cose key tag x5c
    payload: statement,
    secretCoseKey: privateKeyCose
  })

  lines.push(`## X5C / X5T`)

  const diag0 = await cose.key.edn(publicKeyCose)
  lines.push(`
  ~~~~ cbor-diag
  ${diag0}
  ~~~~
      `.trim())

  const diag1 = await cose.scitt.receipt.edn(signature)
  lines.push(diag1)

})

// afterAll(() => {
//   const final = lines.join('\n\n')
//   fs.writeFileSync('test/scitt/examples.md', final)
// })
