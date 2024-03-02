
import * as jose from '../jose-hpke'

import * as cose from '../../src'

import fs from 'fs'
import { publicFromPrivate } from '../../src/cose/key'

let examples = ``

let privateKeyJwk: any
let publicKeyJwk: any

let privateKeyCose: any
let publicKeyCose: any

it('generate private keys', async () => {
  privateKeyJwk = await jose.key.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const k1 = Buffer.from(JSON.stringify(privateKeyJwk, null, 2))
  publicKeyJwk = publicFromPrivate(privateKeyJwk)
  const k1c = await cose.key.convertJsonWebKeyToCoseKey<Map<any, any>>(JSON.parse(k1.toString()))
  k1c.set(2, await cose.key.thumbprint.calculateCoseKeyThumbprintUri(k1c))
  privateKeyCose = k1c
  publicKeyCose = publicFromPrivate(privateKeyCose)
  const k2 = await cose.cbor.encode(k1c)
  examples += `
  
## Private Key

### application/jwk+json

~~~
${k1.toString('hex')}
~~~
{: #private-key-jwk-hex align="left" title="JSON Web Key Bytes"}

~~~json
${k1.toString()}
~~~
{: #private-key-jwk align="left" title="JSON Web Key"}

### application/cose-key

~~~
${Buffer.from(k2).toString('hex')}
~~~
{: #private-key-cose-key align="left" title="COSE Key Bytes"}

~~~ cbor-diag
${(await cose.cbor.diagnose(k2)).trim()}
~~~
{: #private-key-cose-key align="left" title="COSE Key Diagnostic"}

  `.trim() + '\n\n'
})

it('direct encryption', async () => {
  const messsageText = `⌛ My lungs taste the air of Time Blown past falling sands ⌛`
  const aadText = `✨ It’s a dangerous business, Frodo, going out your door. ✨`
  const plaintext = new TextEncoder().encode(messsageText)
  const aad = new TextEncoder().encode(aadText)

  const jwe = await jose.IntegratedEncryption.encrypt(plaintext, publicKeyJwk, aad, { serialization: 'GeneralJson' })
  const decryptedJwe = await jose.IntegratedEncryption.decrypt(jwe, privateKeyJwk, { serialization: 'GeneralJson' })
  expect(new TextDecoder().decode(decryptedJwe.plaintext)).toBe(messsageText)
  expect(new TextDecoder().decode(decryptedJwe.additionalAuthenticatedData)).toBe(aadText)

  const ct = await cose.encrypt.direct({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Direct['HPKE-Base-P256-SHA256-AES128GCM']],
    ]),
    aad,
    plaintext,
    recipients: {
      keys: [{ ...publicKeyJwk, kid: publicKeyCose.get(2) }]
    }
  })
  const pt = await cose.decrypt.direct({
    ciphertext: ct,
    aad,
    recipients: {
      keys: [{ ...privateKeyJwk, kid: publicKeyCose.get(2) }]
    }
  })
  expect(new TextDecoder().decode(pt)).toBe(messsageText)
  examples += `
  
## Direct Encryption

~~~
${messsageText}
~~~
{: #direct-encryption-message align="left" title="Direct Encryption Message"}

~~~
${aadText}
~~~
{: #direct-encryption-addition-authenticated-data align="left" title="Direct Encryption AAD"}

### application/jose+json

~~~
${Buffer.from(JSON.stringify(jwe, null, 2)).toString('hex')}
~~~
{: #direct-ciphertext-jose-bytes align="left" title="Direct JOSE Bytes"}

~~~json
${JSON.stringify(jwe, null, 2)}
~~~
{: #direct-ciphertext-json align="left" title="Direct JOSE JSON"}

### application/cose

~~~
${ct.toString('hex')}
~~~
{: #direct-ciphertext-cose-bytes align="left" title="Direct COSE Bytes"}

~~~ cbor-diag
${(await cose.cbor.diagnose(ct)).trim()}
~~~
{: #direct-ciphertext-cose-diag align="left" title="Direct COSE Diagnostic"}
  
    `.trim() + '\n\n'
})


it('key encryption', async () => {
  const messsageText = `⌛ My lungs taste the air of Time Blown past falling sands ⌛`
  const aadText = `✨ It’s a dangerous business, Frodo, going out your door. ✨`
  const plaintext = new TextEncoder().encode(messsageText)
  const aad = new TextEncoder().encode(aadText)
  const jwe = await jose.KeyEncryption.encrypt({
    protectedHeader: { enc: 'A128GCM' },
    additionalAuthenticatedData: aad,
    plaintext,
    recipients: {
      keys: [publicKeyJwk]
    }
  })
  const decryptedJwe = await jose.KeyEncryption.decrypt({
    jwe,
    recipients: {
      keys: [privateKeyJwk]
    }
  })
  expect(new TextDecoder().decode(decryptedJwe.plaintext)).toBe(messsageText)
  expect(new TextDecoder().decode(decryptedJwe.additionalAuthenticatedData)).toBe(aadText)

  const ct = await cose.encrypt.wrap({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Aead.A128GCM],
    ]),
    aad,
    plaintext,
    recipients: {
      keys: [{ ...publicKeyJwk, kid: publicKeyCose.get(2) }]
    }
  })

  const pt = await cose.decrypt.wrap({
    ciphertext: ct,
    aad,
    recipients: {
      keys: [{ ...privateKeyJwk, kid: publicKeyCose.get(2) }]
    }
  })
  expect(new TextDecoder().decode(pt)).toBe(messsageText)
  examples += `
  
## Key Encryption

~~~
${messsageText}
~~~
{: #key-encryption-message align="left" title="Key Encryption Message"}

~~~
${aadText}
~~~
{: #key-encryption-addition-authenticated-data align="left" title="Key Encryption AAD"}

### application/jose+json

~~~
${Buffer.from(JSON.stringify(jwe, null, 2)).toString('hex')}
~~~
{: #wrap-ciphertext-jose-bytes align="left" title="Key Encryption JOSE Bytes"}

~~~json
${JSON.stringify(jwe, null, 2)}
~~~
{: #wrap-ciphertext-jose-json align="left" title="Key Encryption JOSE JSON"}

### application/cose

~~~
${ct.toString('hex')}
~~~
{: #wrap-ciphertext-cose-bytes align="left" title="Key Encryption COSE Bytes"}

~~~ cbor-diag
${(await cose.cbor.diagnose(ct)).trim()}
~~~
{: #wrap-ciphertext-cose-diag align="left" title="Key Encryption COSE Diagnostic"}
  
    `.trim() + '\n\n'
})


afterAll(() => {
  // fs.writeFileSync('./test/draft-jose-cose-hpke-cookbook/examples.md', examples)
})