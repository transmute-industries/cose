``` ts
import cose from '@transmute/cose'
```

## Generate Private Key

``` ts
const secretCoseKey = await cose.key.generate(-7)
const thumbprintOfSecretKey = await cose.key.thumbprint.uri(secretCoseKey)
const diagnosticOfSecretKey = await cose.key.edn(secretCoseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:tchWR3A4n62lEkNy6LjQIhj-DKzZ5HWBbwLIWLK8lhU
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6a394853...5776736f',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'3adf19c5...591bc5de',       / x public key component        /
  -3: h'ef36404d...a18d3aa7',       / y public key component        /
  -4: h'ee0921dd...bf6f1d17',       / d private key component       /
}
~~~~

## Export Public Key

``` ts
const publicCoseKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicCoseKey)
const diagnosticOfPublicKey = await cose.key.edn(publicCoseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:tchWR3A4n62lEkNy6LjQIhj-DKzZ5HWBbwLIWLK8lhU
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'6a394853...5776736f',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'3adf19c5...591bc5de',       / x public key component        /
  -3: h'ef36404d...a18d3aa7',       / y public key component        /
}
~~~~

## Issue Statement

``` ts
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
      "Tool: Microsoft.SBOMTool-0.0.0-alpha.0.13+build.37"
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
```

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012603...6d706c65',       / Protected                     /
      {},                           / Unprotected                   /
      h'',                          / Detached payload              /
      h'bcbb3bfe...9fc99291'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  3: application/spdx+json,         / Content type                  /
  4: h'6a394853...5776736f',        / Key identifier                /
  13: {                             / CWT Claims                    /
    1: software.vendor.example,     / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  },
}
~~~~

## Verify Signed Statement

``` ts
const verificaton = await cose.scitt.statement.verify({
  statement,
  signedStatement,
  publicCoseKey
})
console.log({ verificaton })
```


~~~~ text
{ verificaton: true }
~~~~

## Issue Receipt

``` ts
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
```

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012604...6d706c65',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -1: [                     / Inclusion proofs (1)          /
            h'83080783...32568964', / Inclusion proof 1             /
          ]
        },
      },
      h'',                          / Detached payload              /
      h'9621ab96...8f1ff150'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'6a394853...5776736f',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
  13: {                             / CWT Claims                    /
    1: transparency.vendor.example, / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  },
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  8,                                / Tree size                     /
  7,                                / Leaf index                    /
  [                                 / Inclusion hashes (3)          /
     h'fc087945...d16378f9'         / Intermediate hash 1           /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2           /
     h'0bdaaed3...32568964'         / Intermediate hash 3           /
  ]
]
~~~~

## Verify Receipt

``` ts
const logIndex = entries.length - 1 // last entry is the signed statement
const verificaton = await cose.scitt.receipt.verify({
  entry: entries[logIndex],
  receipt,
  publicCoseKey
})
console.log({ verificaton })
```


~~~~ text
{ verificaton: true }
~~~~

## Transparent Statement

``` ts
const transparentStatement = await cose.scitt.statement.addReceipt({
  statement: signedStatement,
  receipt
})
const { entry, receipts } = cose.scitt.statement.getEntryReceipts({ transparentStatement })
```

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012603...6d706c65',       / Protected                     /
      {                             / Unprotected                   /
        -333: [                     / Receipts (1)                  /
          h'd284586c...8f1ff150'    / Receipt 1                     /
        ]
      },
      h'',                          / Detached payload              /
      h'bcbb3bfe...9fc99291'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  3: application/spdx+json,         / Content type                  /
  4: h'6a394853...5776736f',        / Key identifier                /
  13: {                             / CWT Claims                    /
    1: software.vendor.example,     / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  },
}
~~~~

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4012604...6d706c65',       / Protected                     /
      {                             / Unprotected                   /
        -222: {                     / Proofs                        /
          -1: [                     / Inclusion proofs (1)          /
            h'83080783...32568964', / Inclusion proof 1             /
          ]
        },
      },
      h'',                          / Detached payload              /
      h'9621ab96...8f1ff150'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'6a394853...5776736f',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
  13: {                             / CWT Claims                    /
    1: transparency.vendor.example, / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  },
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  8,                                / Tree size                     /
  7,                                / Leaf index                    /
  [                                 / Inclusion hashes (3)          /
     h'fc087945...d16378f9'         / Intermediate hash 1           /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2           /
     h'0bdaaed3...32568964'         / Intermediate hash 3           /
  ]
]
~~~~

## X5C / X5T

~~~~ cbor-diag
  {                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'75726e3a...4b755a59',        / Identifier                    /
  3: -35,                           / Algorithm                     /
  -1: 2,                            / Curve                         /
  -2: h'445169ee...498a53f1',       / x public key component        /
  -3: h'0c2469cb...7e9dfd69',       / y public key component        /
  -66666: [                         / X.509 Certificate Chain       /
    h'308201b4...b4e9b233',         / X.509 Certificate             /
    h'308201bf...4eb5f42d',         / X.509 Certificate             /
  ],
}
  ~~~~

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a5182182...3a343536',       / Protected                     /
      {},                           / Unprotected                   /
      h'',                          / Detached payload              /
      h'2e35d325...990e8c54'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  33: [                             / X.509 Certificate Chain       /
    h'308201b4...b4e9b233',         / X.509 Certificate             /
    h'308201bf...4eb5f42d',         / X.509 Certificate             /
  ],
  1: -35,                           / Algorithm                     /
  3: application/json,              / Content type                  /
  4: h'75726e3a...4b755a59',        / Key identifier                /
  13: {                             / CWT Claims                    /
    1: urn:example:123,             / Issuer                        /
    2: urn:example:456,             / Subject                       /
  },
}
~~~~