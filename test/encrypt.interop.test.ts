import cose from 'cose-js';

import { cbor } from '@transmute/cose';



it('symmetric sanity encrypt / decrypt', async () => {
  const plaintext = '❤️‍🔥 Secret message! ❤️‍🔥';
  const key = Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex');
  const headers = {
    p: { alg: 'A128GCM' },
    u: { kid: 'our-secret' }
  };
  const recipient = {
    key
  };
  const ciphertext = await cose.encrypt.create(headers, plaintext, recipient);
  const recoveredPlaintext = await cose.encrypt.read(ciphertext, key);
  expect(recoveredPlaintext.toString('utf8')).toBe(plaintext)
})

it('direct key agreement sanity encrypt / decrypt', async () => {
  const example = {
    "title": "p256-hkdf-256-01: ECDH-ES direct w/ hkdf-sha-256 for 128-bit key",
    "input": {
      "plaintext": "This is the content.",
      "enveloped": {
        "protected": {
          "alg": "A128GCM"
        },
        "recipients": [
          {
            "key": {
              "kty": "EC",
              "kid": "meriadoc.brandybuck@buckland.example",
              "crv": "P-256",
              "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
              "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
              "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
            },
            "protected": {
              "alg": "ECDH-ES"
            },
            "unprotected": {
              "kid": "meriadoc.brandybuck@buckland.example"
            },
            "unsent": {
              "compressed": 0
            }
          }
        ]
      },
      "rng_stream": [
        "02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3",
        "C9CF4DF2FE6C632BF7886413"
      ]
    },
    "intermediates": {
      "AAD_hex": "8367456E637279707443A1010140",
      "CEK_hex": "56074D506729CA40C4B4FE50C6439893",
      "recipients": [
        {
          "Context_hex": "840183F6F6F683F6F6F682188044A1013818",
          "Secret_hex": "4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6"
        }
      ]
    },
    "output": {
      "cbor_diag": "96([h'A10101', {5: h'C9CF4DF2FE6C632BF7886413'}, h'7ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0', [[h'A1013818', {-1: {1: 2, -1: 1, -2: h'98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280', -3: h'F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB'}, 4: h'6D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65'}, h'']]])",
      "cbor": "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540"
    }
  }
  const p = example.input.enveloped.protected;
  const u = undefined;
  const plaintext = Buffer.from(example.input.plaintext);
  function randomSource(bytes: number) {
    if (bytes === 12) {
      return Buffer.from('C9CF4DF2FE6C632BF7886413', 'hex');
    } else {
      return Buffer.from('02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3', 'hex');
    }
  }
  const recipient = [{
    key: {
      kty: example.input.enveloped.recipients[0].key.kty,
      kid: example.input.enveloped.recipients[0].key.kid,
      crv: example.input.enveloped.recipients[0].key.crv,
      x: Buffer.from(example.input.enveloped.recipients[0].key.x, 'base64'),
      y: Buffer.from(example.input.enveloped.recipients[0].key.y, 'base64'),
      d: Buffer.from(example.input.enveloped.recipients[0].key.d, 'base64')
    },
    p: example.input.enveloped.recipients[0].protected,
    u: example.input.enveloped.recipients[0].unprotected
  }];
  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipient, options);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  expect(actual.value[0].toString('hex')).toBe(expected.value[0].toString('hex').toString('hex'))
  expect(actual.value[2].toString('hex')).toBe(expected.value[2].toString('hex').toString('hex'))
  // https://datatracker.ietf.org/doc/html/rfc9052#section-5.1
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = actual.value
  const decodedProtectedHeader = cbor.decodeFirstSync(protectedHeader);
  expect(decodedProtectedHeader.get(1)).toBe(1) // alg : A128GCM
  const [[recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText]] = recipients
  const kid = recipientUnprotectedHeader.get(4)
  const epk = recipientUnprotectedHeader.get(-1)
  expect(kid.toString()).toBe('meriadoc.brandybuck@buckland.example')
  const kty = epk.get(1)
  expect(kty).toBe(2) // kty : EC2
  const crv = epk.get(-1) //
  expect(crv).toBe(1) // crv : P-256
  const decodedRecipientProtectedHeader = cbor.decodeFirstSync(recipientProtectedHeader);
  expect(decodedRecipientProtectedHeader.get(1)).toBe(-25) // alg : ECDH-ES + HKDF-256
})