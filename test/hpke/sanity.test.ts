import fs from 'fs'
import jose from './joseHpke'
import cose from './coseHpke'

it('sanity', async () => {
  const k = await jose.hpke.generate(jose.hpke.Suite0)

  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)


  const c = await jose.hpke.direct.encrypt(m, k.publicKeyJwk)
  const d = await jose.hpke.direct.decrypt(c, k.privateKeyJwk)
  const rpt = new TextDecoder().decode(d)
  expect(rpt).toBe(pt)

  const c2 = await jose.hpke.indirect.encrypt(m, k.publicKeyJwk)
  const d2 = await jose.hpke.indirect.decrypt(c2, k.privateKeyJwk)
  const rpt2 = new TextDecoder().decode(d2)
  expect(rpt2).toBe(pt)


  const k2 = {
    cosePublicKey: cose.hpke.coseKey.importJWK(k.publicKeyJwk),
    cosePrivateKey: cose.hpke.coseKey.importJWK(k.privateKeyJwk)
  }

  const publicKeyEdn = await cose.hpke.coseKey.beautify(k2.cosePublicKey)
  const privateKeyEdn = await cose.hpke.coseKey.beautify(k2.cosePrivateKey)

  const c3 = await cose.hpke.direct.encrypt(m, k2.cosePublicKey)
  fs.writeFileSync('test/hpke/ct.cose', c3)
  const d3 = await cose.hpke.direct.decrypt(c3, k2.cosePrivateKey)
  const rpt3 = new TextDecoder().decode(d3)
  expect(rpt3).toBe(pt)

  const c4 = await cose.hpke.indirect.encrypt(m, k2.cosePublicKey)
  fs.writeFileSync('test/hpke/ct.multi.cose', c4)
  const d4 = await cose.hpke.indirect.decrypt(c4, k2.cosePrivateKey)
  const rpt4 = new TextDecoder().decode(d4)
  expect(rpt4).toBe(pt)

  const final = `
# JOSE

Inspired by https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1

~~~~ text
{
  "protected":"<integrity-protected shared header contents>",
  "unprotected":<non-integrity-protected shared header contents>,
  "recipients":[
   {"header":<per-recipient unprotected header 1 contents>,
    "encrypted_key":"<encrypted key 1 contents>"},
   ...
   {"header":<per-recipient unprotected header N contents>,
    "encrypted_key":"<encrypted key N contents>"}],
  "aad":"<additional authenticated data contents>",
  "iv":"<initialization vector contents>",
  "ciphertext":"<ciphertext contents>",
  "tag":"<authentication tag contents>"
}
~~~~

## Public Key

~~~~ json
${JSON.stringify(k.publicKeyJwk, null, 2)}
~~~~

## Private Key

~~~~ json
${JSON.stringify(k.privateKeyJwk, null, 2)}
~~~~

## HPKE Usage in Direct Key Agreement

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.1

~~~~ json
${JSON.stringify(c, null, 2)}
~~~~

## HPKE Usage in Key Agreement with Key Wrapping mode

https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1.2

~~~~ json
${JSON.stringify(c2, null, 2)}
~~~~

# COSE

Inspired by https://datatracker.ietf.org/doc/html/rfc9052#name-encryption-objects

~~~~ text

COSE_Encrypt = [
  Headers,
  ciphertext : bstr / nil,
  recipients : [+COSE_recipient]
]

COSE_recipient = [
  Headers,
  ciphertext : bstr / nil,
  ? recipients : [+COSE_recipient]
]

COSE_Encrypt0 = [
  Headers,
  ciphertext : bstr / nil,
]

Enc_structure = [
  context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
      "Mac_Recipient" / "Rec_Recipient",
  protected : empty_or_serialized_map,
  external_aad : bstr
]

~~~~

## Public Key

~~~~ cbor-diag
${publicKeyEdn}
~~~~

## Private Key

~~~~ cbor-diag
${privateKeyEdn}
~~~~

## Single Recipient / One Layer Structure 

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.1

~~~~ cbor-diag
[
  h'A20139D90204F7', 
  {
    -22222: h'04F9E269...051458AC'
  }, 
  h'4849CE69...E6982351'
]
~~~~

## Multiple Recipients / Two Layer Structure

See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1.2

~~~~ cbor-diag
... todo
~~~~

  
  `.trim()
  fs.writeFileSync('test/hpke/README.md', final)
})