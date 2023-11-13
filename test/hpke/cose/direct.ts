import crypto from 'crypto'
import * as cbor from 'cbor-web'

import * as coseKey from '../../../src/key'
// eslint-disable-next-line @typescript-eslint/no-var-requires

import { coseSuites, example_suite_label, encapsulated_key_header_label, PublicCoseKeyMap, SecretCoseKeyMap } from '../common'


const directMode = {
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
    const protectedHeaderMap = new Map();
    protectedHeaderMap.set(1, alg) // alg : TBD / restrict alg by recipient key /
    const encodedProtectedHeader = cbor.encode(protectedHeaderMap)
    const unprotectedHeaderMap = new Map();
    unprotectedHeaderMap.set(4, kid) // kid : ...
    unprotectedHeaderMap.set(encapsulated_key_header_label, sender.enc) // https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-07#section-3.1
    const external_aad = Buffer.from(new Uint8Array())
    const Enc_structure = ["Encrypt0", encodedProtectedHeader, external_aad]
    const internal_aad = cbor.encode(Enc_structure)
    const ciphertext = await sender.seal(plaintext, internal_aad)
    return cbor.encode([
      encodedProtectedHeader,
      unprotectedHeaderMap,
      ciphertext
    ])

    // cbor.encodeAsync(new Tagged(Sign1Tag, coseSign1Structure), { canonical: true })

  },
  decrypt: async (coseEnc: ArrayBuffer, recipientPrivate: SecretCoseKeyMap) => {
    const decoded = await cbor.decode(coseEnc)
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
    const [encodedProtectedHeader, unprotectedHeaderMap, ciphertext] = decoded
    const external_aad = Buffer.from(new Uint8Array())
    const Enc_structure = ["Encrypt0", encodedProtectedHeader, external_aad]
    const internal_aad = cbor.encode(Enc_structure)
    const enc = unprotectedHeaderMap.get(encapsulated_key_header_label)
    const recipient = await coseSuites[alg].createRecipientContext({
      recipientKey: privateKey, // rkp (CryptoKeyPair) is also acceptable.
      enc
    })
    const pt = await recipient.open(ciphertext, internal_aad)
    return new Uint8Array(pt)
  }
}

export default directMode