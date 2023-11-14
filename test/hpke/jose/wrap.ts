import crypto from 'crypto'
import * as jose from 'jose'

import { joseSuites, Suite0, craftProtectedHeader } from '../common'

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
    const sender = await joseSuites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })
    const encodedEnc = jose.base64url.encode(new Uint8Array(sender.enc))
    const encodedProtectedHeader = craftProtectedHeader({ enc: 'A128GCM' })
    const internal_aad = jose.base64url.decode(encodedProtectedHeader)
    const encCEK = await sender.seal(cek, internal_aad)
    const unprotected = {
      recipients: [
        {
          kid: recipientPublicKeyJwk.kid,
          encapsulated_key: encodedEnc,
          encrypted_key: jose.base64url.encode(new Uint8Array(encCEK))
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
    const internal_aad = jose.base64url.decode(jwe.protected)
    const recipientObj = jwe.unprotected.recipients.find((r: any) => {
      return r.kid === privateKeyJwk.kid
    })
    const decodedEnc = jose.base64url.decode(recipientObj.encapsulated_key)
    const recipient = await joseSuites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc: decodedEnc
    })
    const ct = jose.base64url.decode(recipientObj.encrypted_key)
    const cek = await recipient.open(ct, internal_aad)
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

export default indirectMode