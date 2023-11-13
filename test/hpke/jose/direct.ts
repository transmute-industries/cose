import crypto from 'crypto'
import * as jose from 'jose'
import { joseSuites, craftProtectedHeader, Suite0 } from '../common'


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
    const sender = await joseSuites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })
    const encodedEnc = jose.base64url.encode(new Uint8Array(sender.enc))

    const encodedProtectedHeader = craftProtectedHeader({ alg })
    const aad = jose.base64url.decode(encodedProtectedHeader)

    // todo: generate content encryption key
    const ct = await sender.seal(plaintext, aad)
    const ciphertext = jose.base64url.encode(new Uint8Array(ct))
    const unprotectedHeader = { kid: recipientPublicKeyJwk.kid, encapsulated_key: encodedEnc }
    return {
      protected: encodedProtectedHeader,
      unprotected: jose.base64url.encode(JSON.stringify(unprotectedHeader)),
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
    const unprotected = JSON.parse(jose.base64url.decode(jwe.unprotected).toString())

    const decodedEnc = jose.base64url.decode(unprotected.encapsulated_key)
    const recipient = await joseSuites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc: decodedEnc
    })
    const ct = jose.base64url.decode(jwe.ciphertext)
    const pt = await recipient.open(ct, aad)
    return new Uint8Array(pt)
  }
}

export default directMode