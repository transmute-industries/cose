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
urn:ietf:params:oauth:ckt:sha-256:KV04tw9Jg7486nLpEoO_TqKOeeAyOsik5KShTUOcErs
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'64542d39...63427373',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'ca81c7c5...1ddebb30',       / x public key component        /
  -3: h'18c5bf4d...b26539d5',       / y public key component        /
  -4: h'a793a267...af2aba46',       / d private key component       /
}
~~~~

## Export Public Key

``` ts
const publicCoseKey = await cose.key.utils.publicFromPrivate(secretCoseKey)
const thumbprintOfPublicKey = await cose.key.thumbprint.uri(publicCoseKey)
const diagnosticOfPublicKey = await cose.key.edn(publicCoseKey)
```

~~~~ text
urn:ietf:params:oauth:ckt:sha-256:KV04tw9Jg7486nLpEoO_TqKOeeAyOsik5KShTUOcErs
~~~~

~~~~ cbor-diag
{                                   / COSE Key                      /
  1: 2,                             / Type                          /
  2: h'64542d39...63427373',        / Identifier                    /
  3: -7,                            / Algorithm                     /
  -1: 1,                            / Curve                         /
  -2: h'ca81c7c5...1ddebb30',       / x public key component        /
  -3: h'18c5bf4d...b26539d5',       / y public key component        /
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
      h'ab1e9bc7...8bbe2c31'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  3: application/spdx+json,         / Content type                  /
  4: h'64542d39...63427373',        / Key identifier                /
  13: {                             / CWT Claims                    /
    1: software.vendor.example,     / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
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
      h'3179f823...cf32c915'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'64542d39...63427373',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
  13: {                             / CWT Claims                    /
    1: transparency.vendor.example, / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  8,                                / Tree size                     /
  7,                                / Leaf index                    /
  [                                 / Inclusion hashes (3)          /
     h'4f0e24ca...de461bc0'         / Intermediate hash 1           /
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
          h'd284586c...cf32c915'    / Receipt 1                     /
        ]
      },
      h'',                          / Detached payload              /
      h'ab1e9bc7...8bbe2c31'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  3: application/spdx+json,         / Content type                  /
  4: h'64542d39...63427373',        / Key identifier                /
  13: {                             / CWT Claims                    /
    1: software.vendor.example,     / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
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
      h'3179f823...cf32c915'        / Signature                     /
    ]
)
~~~~

~~~~ cbor-diag
{                                   / Protected                     /
  1: -7,                            / Algorithm                     /
  4: h'64542d39...63427373',        / Key identifier                /
  -111: 1,                          / Verifiable Data Structure     /
  13: {                             / CWT Claims                    /
    1: transparency.vendor.example, / Issuer                        /
    2: vendor.product.example,      / Subject                       /
  }
}
~~~~

~~~~ cbor-diag
[                                   / Inclusion proof 1             /
  8,                                / Tree size                     /
  7,                                / Leaf index                    /
  [                                 / Inclusion hashes (3)          /
     h'4f0e24ca...de461bc0'         / Intermediate hash 1           /
     h'75f177fd...2e73a8ab'         / Intermediate hash 2           /
     h'0bdaaed3...32568964'         / Intermediate hash 3           /
  ]
]
~~~~