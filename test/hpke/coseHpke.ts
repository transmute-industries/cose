import crypto from 'crypto'
import * as cbor from 'cbor-web'
import * as jose from 'jose'
import { AeadId, KdfId, KemId, CipherSuite, } from 'hpke-js'

import * as coseKey from '../../src/key'
// eslint-disable-next-line @typescript-eslint/no-var-requires

type Suite0 = `HPKE-Base-P256-SHA256-AES128GCM`
const Suite0 = 'HPKE-Base-P256-SHA256-AES128GCM' as Suite0 // aka APPLE-HPKE-v1

type PublicCoseKeyMap = Map<string | number, string | number | Buffer | ArrayBuffer>

type SecretCoseKeyMap = Map<string | number, string | number | Buffer | ArrayBuffer>


const suites = {
  [-55555]: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
} as Record<number, CipherSuite>

const directMode = {
  // todo: use jwks instead...
  encrypt: async (plaintext: Uint8Array, recipientPublic: PublicCoseKeyMap) => {
    const alg = recipientPublic.get(3) || -55555
    const kid = recipientPublic.get(4)
    if (alg !== -55555) {
      throw new Error('Unsupported algorithm')
    }
    const publicKeyJwk = coseKey.exportJWK(recipientPublic);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      [],
    )
    const sender = await suites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })

    const protectedHeaderMap = new Map();
    protectedHeaderMap.set(1, alg) // alg : TBD / restrict alg by recipient key /
    protectedHeaderMap.set(4, kid) // kid : ...
    const encodedProtectedHeader = cbor.encode(protectedHeaderMap)

    const unprotectedHeaderMap = new Map();
    unprotectedHeaderMap.set(-22222, sender.enc) // https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1

    const external_aad = Buffer.from(new Uint8Array())
    const Enc_structure = ["Encrypt0", encodedProtectedHeader, external_aad]
    // .... so we don't use this? ... confused.

    const aad = encodedProtectedHeader
    const ciphertext = await sender.seal(plaintext, aad)
    return cbor.encode([
      encodedProtectedHeader,
      unprotectedHeaderMap,
      ciphertext
    ])

  },
  decrypt: async (coseEnc: ArrayBuffer, recipientPrivate: SecretCoseKeyMap) => {
    const decoded = await cbor.decode(coseEnc)
    const alg = recipientPrivate.get(3) || -55555
    if (alg !== -55555) {
      throw new Error('Unsupported algorithm')
    }
    const privateKeyJwk = coseKey.exportJWK(recipientPrivate) as any;
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

    const [encodedProtectedHeader, unprotectedHeaderMap, ciphertext] = decoded
    const aad = encodedProtectedHeader
    const enc = unprotectedHeaderMap.get(-22222)
    const recipient = await suites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc
    })
    const pt = await recipient.open(ciphertext, aad)
    return new Uint8Array(pt)
  }
}

const indirectMode = {
  // todo: use jwks instead...
  encrypt: async (plaintext: Uint8Array, recipientPublic: PublicCoseKeyMap) => {
    const alg = recipientPublic.get(3) || -55555
    const kid = recipientPublic.get(4)
    if (alg !== -55555) {
      throw new Error('Unsupported algorithm')
    }
    const publicKeyJwk = coseKey.exportJWK(recipientPublic);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      [],
    )
    const sender = await suites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })

    const protectedHeaderMap = new Map();
    protectedHeaderMap.set(1, alg) // alg : TBD / restrict alg by recipient key /

    const encodedProtectedHeader = cbor.encode(protectedHeaderMap)

    const external_aad = Buffer.from(new Uint8Array())
    // not used?

    // 16 for AES-128-GCM
    const cek = crypto.randomBytes(16)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const unprotectedHeaderMap = new Map();
    unprotectedHeaderMap.set(-22222, sender.enc) // https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1

    unprotectedHeaderMap.set(4, kid) // kid : ...
    unprotectedHeaderMap.set(5, iv) // https://datatracker.ietf.org/doc/html/rfc8152#appendix-C.4.1

    const key = await crypto.subtle.importKey('raw', cek, {
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])
    const encrypted_content = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      plaintext,
    );

    const aad = encodedProtectedHeader
    const encCEK = await sender.seal(cek, aad)

    // why are we sending this same protected header to every recipient here?
    const recipient = [encodedProtectedHeader, unprotectedHeaderMap, encCEK]
    return cbor.encode([
      encodedProtectedHeader,
      encrypted_content,
      [recipient]
    ])

  },
  decrypt: async (coseEnc: ArrayBuffer, recipientPrivate: SecretCoseKeyMap) => {
    const alg = recipientPrivate.get(3) || -55555
    if (alg !== -55555) {
      throw new Error('Unsupported algorithm')
    }
    const privateKeyJwk = coseKey.exportJWK(recipientPrivate) as any;
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
    const decoded = await cbor.decode(coseEnc)
    const [encodedProtectedHeader, encrypted_content, recipients] = decoded

    const recipientArray = recipients.find(([ph, uphm, encCek]: any) => {
      return uphm.get(4) === recipientPrivate.get(3) // header.kid === privateKey.kid
    })
    const [ph, uphm, encCek] = recipientArray
    // why repeat protected header?
    const aad = encodedProtectedHeader
    const enc = uphm.get(-22222)
    const iv = uphm.get(5)
    const recipient = await suites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc
    })
    const cek = await recipient.open(encCek, aad)
    const key = await crypto.subtle.importKey('raw', cek, {   //this is the algorithm options
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])
    const decrypted_content = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted_content,
    );
    return decrypted_content
  }
}

const hpke = {
  Suite0,
  suites,
  coseKey,
  direct: directMode,
  indirect: indirectMode
}
const api = { hpke }
export default api