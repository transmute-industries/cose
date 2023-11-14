import crypto from 'crypto'
import * as cbor from 'cbor-web'

import * as coseKey from '../../../src/key'

import { COSE_EncryptTag, coseSuites, example_suite_label, encapsulated_key_header_label, PublicCoseKeyMap, SecretCoseKeyMap } from '../common'

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

    // 16 for AES-128-GCM
    const cek = crypto.randomBytes(16)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const layer1UnprotectedHeader = new Map();
    layer1UnprotectedHeader.set(encapsulated_key_header_label, sender.enc) // https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1
    layer1UnprotectedHeader.set(4, kid) // kid : ...

    // should we mitigate cross mode attack on aead here?
    // let external_aad be the layer 0 protected header
    const external_aad = Buffer.from(layer0EncodedProtectedHeader)
    const Enc_structure = ["Encrypt0", layer1EncodedProtectedHeader, external_aad]
    const internal_aad = cbor.encode(Enc_structure)
    const encCEK = await sender.seal(cek, internal_aad)
    const recipient = [layer1EncodedProtectedHeader, layer1UnprotectedHeader, encCEK]
    const layer0UnprotectedHeader = new Map()
    layer0UnprotectedHeader.set(5, Buffer.from(iv)) // https://datatracker.ietf.org/doc/html/rfc8152#appendix-C.4.1

    const key = await crypto.subtle.importKey('raw', cek, {
      name: "AES-GCM",
    }, true, ["encrypt", "decrypt"])
    const encrypted_content = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      plaintext,
    );

    const coseEncrypt = [
      layer0EncodedProtectedHeader,
      layer0UnprotectedHeader,
      encrypted_content,
      [recipient]
    ]

    return cbor.encodeAsync(new cbor.Tagged(COSE_EncryptTag, coseEncrypt), { canonical: true })

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
    const decodedTagged = await cbor.decode(coseEnc)
    const decoded = decodedTagged.value
    const [layer0EncodedProtectedHeader, layer0UnprotectedHeader, encrypted_content, recipients] = decoded
    const recipientArray = recipients.find(([ph, uphm, encCek]: any) => {
      return uphm.get(4) === recipientPrivate.get(2) // header.kid === privateKey.kid
    })
    const [layer1EncodedProtectedHeader, uphm, encCek] = recipientArray
    // mitigating cross mode attacks on aead here.
    const external_aad = Buffer.from(layer0EncodedProtectedHeader)
    const enc = uphm.get(encapsulated_key_header_label)
    const iv = layer0UnprotectedHeader.get(5)
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