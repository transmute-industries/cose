import crypto from 'crypto'
import * as jose from 'jose'
import fs from 'fs'
import { AeadId, KdfId, KemId, CipherSuite, } from 'hpke-js'
// eslint-disable-next-line @typescript-eslint/no-var-requires

// https://developer.apple.com/documentation/passkit/wallet/verifying_wallet_identity_requests?language=objc

type Suite0 = `HPKE-Base-P256-SHA256-AES128GCM`
const Suite0 = 'HPKE-Base-P256-SHA256-AES128GCM' as Suite0 // aka APPLE-HPKE-v1

type Suite0CurveName = `P-256`

type SuiteNames = Suite0
type CurveNames = Suite0CurveName

const suites = {
  [Suite0]: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
} as Record<SuiteNames, CipherSuite>

const algToCrv = {
  [Suite0]: 'P-256',
} as Record<SuiteNames, CurveNames>

const generate = async (alg: Suite0) => {
  const { publicKey, privateKey } = await jose.generateKeyPair(
    'ECDH-ES+A128KW',
    { extractable: true, crv: algToCrv[alg] },
  )
  const publicKeyJwk = await jose.exportJWK(publicKey)
  const privateKeyJwk = await jose.exportJWK(privateKey)
  const kid = `test-key-42`
  return {
    publicKeyJwk: {
      kty: publicKeyJwk.kty,
      crv: publicKeyJwk.crv,
      alg,
      kid,
      x: publicKeyJwk.x,
      y: publicKeyJwk.y,
      use: 'enc',
      key_ops: ['deriveBits'],
    },
    privateKeyJwk: {
      kty: privateKeyJwk.kty,
      crv: privateKeyJwk.crv,
      alg,
      kid,
      x: privateKeyJwk.x,
      y: privateKeyJwk.y,
      d: privateKeyJwk.d,
      key_ops: ['deriveBits'],
    },
  }
}

// https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-01#section-4.1.1
// In both modes, the sender MUST specify the 'alg' parameter in the protected header to indicate the use of HPKE.

const craftProtectedHeader = ({ alg, enc, kid }: { alg: Suite0, enc?: string, kid?: string }) => {
  return jose.base64url.encode(JSON.stringify({
    alg, enc, kid
  }))
}

const directMode = {
  // todo: use jwks instead...
  encrypt: async (plaintext: Uint8Array, recipientPublicKeyJwk: any) => {
    const publicKeyJwk = JSON.parse(JSON.stringify(recipientPublicKeyJwk))
    const { alg }: { alg: Suite0 } = publicKeyJwk
    if (alg !== Suite0) {
      throw new Error('Unsupported algorithm')
    }
    delete publicKeyJwk.alg
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      {
        name: 'ECDH',
        namedCurve: publicKeyJwk.crv,
      },
      true,
      [],
    )
    const sender = await suites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })
    const encodedEnc = jose.base64url.encode(new Uint8Array(sender.enc))

    const encodedProtectedHeader = craftProtectedHeader({ alg, enc: encodedEnc, kid: recipientPublicKeyJwk.kid })
    const aad = jose.base64url.decode(encodedProtectedHeader)

    // todo: generate content encryption key
    const ct = await sender.seal(plaintext, aad)
    const ciphertext = jose.base64url.encode(new Uint8Array(ct))
    return {
      protected: encodedProtectedHeader,
      ciphertext,
    }
  },
  decrypt: async (jwe: any, recipientPrivateKeyJwk: any) => {
    const privateKeyJwk = JSON.parse(JSON.stringify(recipientPrivateKeyJwk))
    const { alg }: { alg: Suite0 } = privateKeyJwk
    if (alg !== Suite0) {
      throw new Error('Unsupported algorithm')
    }
    // web crypto doesn't know about HPKE yet.
    delete privateKeyJwk.alg
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      privateKeyJwk,
      {
        name: 'ECDH',
        namedCurve: privateKeyJwk.crv,
      },
      true,
      ['deriveBits'],
    )

    const aad = jose.base64url.decode(jwe.protected)
    const decodedUntrustedProtectedHeader = new TextDecoder().decode(aad)
    const parsedUntrustedProtectedHeader = JSON.parse(decodedUntrustedProtectedHeader)
    const decodedEnc = jose.base64url.decode(parsedUntrustedProtectedHeader.enc)
    const recipient = await suites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc: decodedEnc
    })
    const ct = jose.base64url.decode(jwe.ciphertext)
    const pt = await recipient.open(ct, aad)
    return new Uint8Array(pt)
  }
}

const indirectMode = {
  encrypt: async (plaintext: Uint8Array, recipientPublicKeyJwk: any) => {
    const publicKeyJwk = JSON.parse(JSON.stringify(recipientPublicKeyJwk))
    const { alg }: { alg: Suite0 } = publicKeyJwk
    if (alg !== Suite0) {
      throw new Error('Unsupported algorithm')
    }
    delete publicKeyJwk.alg
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      {
        name: 'ECDH',
        namedCurve: publicKeyJwk.crv,
      },
      true,
      [],
    )

    // 16 for AES-128-GCM
    const cek = crypto.randomBytes(16)



    // TODO const ciphertext = ... AES-128-GCM(cek, message)

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.importKey('raw', cek, {   //this is the algorithm options
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])

    const encrypted_content = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      plaintext,
    );


    const ciphertext = jose.base64url.encode(new Uint8Array(encrypted_content))

    const sender = await suites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })

    const encodedEnc = jose.base64url.encode(new Uint8Array(sender.enc))

    const encodedProtectedHeader = craftProtectedHeader({ alg })
    const aad = jose.base64url.decode(encodedProtectedHeader)

    const ct = await sender.seal(cek, aad)

    const unprotected = {
      recipients: [
        {
          kid: recipientPublicKeyJwk.kid,
          enc: encodedEnc,
          encrypted_key: jose.base64url.encode(new Uint8Array(ct))
        }
      ]
    }
    return {
      protected: encodedProtectedHeader,
      unprotected,
      iv: jose.base64url.encode(iv),
      ciphertext,
    }
  },
  decrypt: async (jwe: any, recipientPrivateKeyJwk: any) => {
    const privateKeyJwk = JSON.parse(JSON.stringify(recipientPrivateKeyJwk))
    const { alg }: { alg: Suite0 } = privateKeyJwk
    if (alg !== Suite0) {
      throw new Error('Unsupported algorithm')
    }
    // web crypto doesn't know about HPKE yet.
    delete privateKeyJwk.alg
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      privateKeyJwk,
      {
        name: 'ECDH',
        namedCurve: privateKeyJwk.crv,
      },
      true,
      ['deriveBits'],
    )
    const aad = jose.base64url.decode(jwe.protected)
    // const decodedUntrustedProtectedHeader = new TextDecoder().decode(aad)
    // const parsedUntrustedProtectedHeader = JSON.parse(decodedUntrustedProtectedHeader)

    const recipientObj = jwe.unprotected.recipients.find((r: any) => {
      return r.kid === privateKeyJwk.kid
    })

    const decodedEnc = jose.base64url.decode(recipientObj.enc)
    const recipient = await suites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc: decodedEnc
    })
    const ct = jose.base64url.decode(recipientObj.encrypted_key)
    const cek = await recipient.open(ct, aad)
    const iv = jose.base64url.decode(jwe.iv)
    const key = await crypto.subtle.importKey('raw', cek, {   //this is the algorithm options
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])
    const ciphertext = jose.base64url.decode(jwe.ciphertext)
    const decrypted_content = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext,
    );
    return decrypted_content
  }
}

const hpke = { Suite0, suites, generate, direct: directMode, indirect: indirectMode }



it('sanity', async () => {
  const k = await hpke.generate(hpke.Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const c = await hpke.direct.encrypt(m, k.publicKeyJwk)
  const d = await hpke.direct.decrypt(c, k.privateKeyJwk)
  const rpt = new TextDecoder().decode(d)
  expect(rpt).toBe(pt)

  const c2 = await hpke.indirect.encrypt(m, k.publicKeyJwk)
  const d2 = await hpke.indirect.decrypt(c2, k.privateKeyJwk)
  const rpt2 = new TextDecoder().decode(d2)
  expect(rpt2).toBe(pt)

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

... todo

## Private Key

... todo

## Envelope

... todo
  
  `.trim()
  fs.writeFileSync('test/hpke/README.md', final)
})