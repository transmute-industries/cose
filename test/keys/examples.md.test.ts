import fs from 'fs'
import cose from '../../src'
import { makeRfcCodeBlock } from '../../src/rfc/beautify/makeRfcCodeBlock'

const lines = [] as string[]

it('can generate markdown examples', async () => {
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
})

it('x5c / x5t examples', async () => {
  const jwkWithX509 = {
    "kty": "EC",
    "x": "RFFp7pyHz8LNwfzv5Nm9Gj54KRena0ppOP97xwmk11qRks5ETTr4EPizXexJilPx",
    "y": "DCRpyw6zW8nWeje3tl2KKObt9_vUBVD1uoSEp-kNRzYB3Hfo6DVRgSqE28l-nf1p",
    "crv": "P-384",
    "alg": "ES384",
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tsuna-Iyuwy4T_HuTuT8kTGGc7yqmiqinaWkWfmKuZY",
    "x5t#S256": "y3aITzjZWqXeViSmaCmVyNTllEMkFUSrP3AidYCsR90",
    "x5c": [
      "MIIBtDCCATmgAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowIDENMAsGA1UEAxMEVGVzdDEPMA0GA1UECgwG0JTQvtC8MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERFFp7pyHz8LNwfzv5Nm9Gj54KRena0ppOP97xwmk11qRks5ETTr4EPizXexJilPxDCRpyw6zW8nWeje3tl2KKObt9/vUBVD1uoSEp+kNRzYB3Hfo6DVRgSqE28l+nf1po1UwUzAyBgNVHREEKzAphidkaWQ6d2ViOmlzc3Vlci5rZXkudHJhbnNwYXJlbmN5LmV4YW1wbGUwHQYDVR0OBBYEFBVkRlPB9mmvVdhL9KiFgd0MgWvkMAoGCCqGSM49BAMDA2kAMGYCMQCVStwHFVyaI9StLb96ToC8g5YG+q5j4vHVfH+EmQYfNuWa04JY5ZRw6NhLcdbQr3oCMQCRgwhMlxhn6d4oZ2w1Efd3uTIPcHt4g+EehMU1bEI7+x6i14w1SMWbU6vSh7TpsjM=",
      "MIIBvzCCAUagAwIBAgIBATAKBggqhkjOPQQDAzASMRAwDgYDVQQDEwdUZXN0IENBMB4XDTIwMDEwMTA2MDAwMFoXDTIwMDEwMzA2MDAwMFowEjEQMA4GA1UEAxMHVGVzdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABOsqL0satR5HAQ0+vBJKMlTv1cYQ0rg5I5z3K98GaEhxSUSvB0bk4Nf6VFOYyu5IS4lunr/XLmt/VIAWe/5qyisFQytWsiMzulXtVGxQ4pCbh1HTQ2dmRdg0WSU6pB0GtaNwMG4wTQYDVR0RBEYwRKAfBgkrBgEEAYI3GQGgEgQQrk8d+Ox90BGnZQCgyR5r9oYhZGlkOndlYjpyb290LnRyYW5zcGFyZW5jeS5leGFtcGxlMB0GA1UdDgQWBBRbPYmz753IRbpu0BWh/VGCgqf/qTAKBggqhkjOPQQDAwNnADBkAjAWGMj/8vkLoAXPkqfDRuHOZTxWMHylpUsqsnkGR2tNh8xNZDXzFQvzdafFUJqvlS4CMA0cUi/RJC3ff1x2if6Ua8jMTdh76BXBMxTDZehsu4ShdeLhbtJT9cHMIU7PTrX0LQ=="
    ]
  }
  const k1 = await cose.key.importJWK(jwkWithX509)
  const cktUri = await cose.key.thumbprint.calculateCoseKeyThumbprintUri(k1)
  expect(cktUri).toBe('urn:ietf:params:oauth:ckt:sha-256:Tm3huDVZp7nlXlJG5DzkY_NvhOAf8R-qZ_PiZwtLc5g')
  const diag = await cose.key.edn(k1)
  expect(diag.includes('-66666')).toBe(true) // private label for x5c

  lines.push('#### x5c / x5t')
  lines.push(`
~~~~ json
${JSON.stringify(jwkWithX509, null, 2)}
~~~~`)
  lines.push(`
~~~~text
${cktUri}
~~~~
    `.trim())

  lines.push(`
~~~~ cbor-diag
${diag}
~~~~
    `.trim())
})

afterAll(() => {
  const final = lines.join('\n\n')
  fs.writeFileSync('test/keys/examples.md', final)
})
