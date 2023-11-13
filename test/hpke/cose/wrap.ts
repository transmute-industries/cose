import crypto from 'crypto'
import * as cbor from 'cbor-web'

import * as coseKey from '../../../src/key'

import { coseSuites, example_suite_label, encapsulated_key_header_label, PublicCoseKeyMap, SecretCoseKeyMap } from '../common'

const indirectMode = {
  // todo: use jwks instead...
  encrypt: async (plaintext: Uint8Array, recipientPublic: PublicCoseKeyMap) => {
    const alg = recipientPublic.get(3) || example_suite_label
    const kid = recipientPublic.get(2)
    if (alg !== example_suite_label) {
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
    const sender = await coseSuites[alg].createSenderContext({
      recipientPublicKey: publicKey,
    })
    const layer0ProtectedHeaderMap = new Map()
    layer0ProtectedHeaderMap.set(1, 1) // A128GCM / optional for HPKE, required for mixed key agreement? /
    const layer0EncodedProtectedHeader = cbor.encode(layer0ProtectedHeaderMap)
    const layer1ProtectedHeaderMap = new Map();
    layer1ProtectedHeaderMap.set(1, alg) // alg : TBD / restrict alg by recipient key /
    const layer1EncodedProtectedHeader = cbor.encode(layer1ProtectedHeaderMap)
    const external_aad = Buffer.from(new Uint8Array())
    // 16 for AES-128-GCM
    const cek = crypto.randomBytes(16)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const unprotectedHeaderMap = new Map();
    unprotectedHeaderMap.set(encapsulated_key_header_label, sender.enc) // https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1
    unprotectedHeaderMap.set(4, kid) // kid : ...
    unprotectedHeaderMap.set(5, Buffer.from(iv)) // https://datatracker.ietf.org/doc/html/rfc8152#appendix-C.4.1
    const key = await crypto.subtle.importKey('raw', cek, {
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])
    const encrypted_content = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      plaintext,
    );
    const Enc_structure = ["Encrypt0", layer1EncodedProtectedHeader, external_aad]
    const internal_aad = cbor.encode(Enc_structure)
    const encCEK = await sender.seal(cek, internal_aad)
    const recipient = [layer1EncodedProtectedHeader, unprotectedHeaderMap, encCEK]
    return cbor.encode([
      layer0EncodedProtectedHeader,
      encrypted_content,
      [recipient]
    ])

  },
  decrypt: async (coseEnc: ArrayBuffer, recipientPrivate: SecretCoseKeyMap) => {
    const alg = recipientPrivate.get(3) || example_suite_label
    if (alg !== example_suite_label) {
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
    const [layer0EncodedProtectedHeader, encrypted_content, recipients] = decoded
    const recipientArray = recipients.find(([ph, uphm, encCek]: any) => {
      return Buffer.from(uphm.get(4)).toString() === Buffer.from(recipientPrivate.get(2) as any).toString() // header.kid === privateKey.kid
    })
    const [layer1EncodedProtectedHeader, uphm, encCek] = recipientArray
    const external_aad = Buffer.from(new Uint8Array())
    const enc = uphm.get(encapsulated_key_header_label)
    const iv = uphm.get(5)
    const recipient = await coseSuites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc
    })
    const Enc_structure = ["Encrypt0", layer1EncodedProtectedHeader, external_aad]
    const internal_aad = cbor.encode(Enc_structure)
    const cek = await recipient.open(encCek, internal_aad)
    const decodedLayer0Header = cbor.decode(layer0EncodedProtectedHeader)
    const layer0Alg = decodedLayer0Header.get(1)
    if (layer0Alg !== 1 /* "AES-GCM" */) {
      throw new Error('Unsupported layer 0 alg')
    }
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

export default indirectMode