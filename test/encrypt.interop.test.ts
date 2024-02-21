import cose from 'cose-js';

import * as transmute from '../src'

it('p256-hkdf-256-01: ECDH-ES direct w/ hkdf-sha-256 for 128-bit key', async () => {
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
  const actual = transmute.cbor.decodeFirstSync(buf);
  // console.log(actual)
  const expected = transmute.cbor.decodeFirstSync(example.output.cbor);
  expect(actual.value[0].toString('hex')).toBe(expected.value[0].toString('hex').toString('hex'))
  expect(actual.value[2].toString('hex')).toBe(expected.value[2].toString('hex').toString('hex'))
  // https://datatracker.ietf.org/doc/html/rfc9052#section-5.1
  const [protectedHeader, unprotectedHeader, ciphertext, recipients] = actual.value
  expect(unprotectedHeader.get(5).toString('hex')).toBe(Buffer.from('C9CF4DF2FE6C632BF7886413', 'hex').toString('hex')) // iv
  const decodedProtectedHeader = transmute.cbor.decodeFirstSync(protectedHeader);
  expect(decodedProtectedHeader.get(1)).toBe(1) // alg : A128GCM
  const [[recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText]] = recipients
  const kid = recipientUnprotectedHeader.get(4)
  const epk = recipientUnprotectedHeader.get(-1)
  // console.log(epk)
  expect(kid.toString()).toBe('meriadoc.brandybuck@buckland.example')
  const kty = epk.get(1)
  expect(kty).toBe(2) // kty : EC2
  const crv = epk.get(-1) //
  expect(crv).toBe(1) // crv : P-256
  const decodedRecipientProtectedHeader = transmute.cbor.decodeFirstSync(recipientProtectedHeader);
  expect(decodedRecipientProtectedHeader.get(1)).toBe(-25) // alg : ECDH-ES + HKDF-256
  expect(recipientCipherText.length).toBe(0)
  const decrypted = await transmute.decrypt.direct({
    ciphertext: buf,
    recipients: {
      keys: [{
        "kty": "EC",
        "kid": "meriadoc.brandybuck@buckland.example",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(Buffer.from(decrypted).toString()).toBe('This is the content.')
})


it('p256-wrap-128-01: ECDH-ES direct w/ key wrap 128 for 128-bit key', async () => {
  const example = {
    "title": "p256-wrap-128-01: ECDH-ES direct w/ key wrap 128 for 128-bit key",
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
              "alg": "ECDH-ES-A128KW"
            },
            "unprotected": {
              "kid": "meriadoc.brandybuck@buckland.example",
              "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
                "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"
              }
            }
          }
        ]
      },
      "rng_stream": [
        "B2353161740AACF1F7163647984B522A",
        "02D1F7E6F26C43D4868D87CE",
        "848DF1C3C9CF4DF2FE6C632BF7886413F76E885255273703EE32E5A427A34F7B"
      ]
    },
    "intermediates": {
      "AAD_hex": "8367456E637279707443A1010140", // good
      "CEK_hex": "B2353161740AACF1F7163647984B522A",
      "recipients": [
        {
          "Context_hex": "842283F6F6F683F6F6F682188044A101381C",
          "Secret_hex": "EE45F7C389FDB89923CA67C0E0CD29802DEC8F514EB818054BEEDD5DAFA78048", // good
          "KEK_hex": "7C60CB35A78B24DCF40A394395E9E8CD"
        }
      ]
    },
    "output": {
      "cbor_diag": "96([h'A10101', {5: h'02D1F7E6F26C43D4868D87CE'}, h'64F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B', [[h'A101381C', {-1: {1: 2, -1: 1, -2: h'ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B', -3: h'D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD602'}, 4: h'6D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65'}, h'D23BCA11C3F8E35BF6F81412794E159772E946FF4FB31BD1']]])",
      "cbor": "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381CA220A401022001215820ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B225820D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD6020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818D23BCA11C3F8E35BF6F81412794E159772E946FF4FB31BD1"
    }
  }
  const expected = transmute.cbor.decode(Buffer.from(example.output.cbor, 'hex'))
  const [protectedHeader, , ciphertext, recipients] = expected.value
  const decodedProtectedHeader = transmute.cbor.decodeFirstSync(protectedHeader);
  expect(decodedProtectedHeader.get(1)).toBe(1) // alg : A128GCM
  const [[recipientProtectedHeader, recipientUnprotectedHeader, recipientCipherText]] = recipients
  const kid = recipientUnprotectedHeader.get(4)
  const epk = recipientUnprotectedHeader.get(-1)
  expect(kid.toString()).toBe('meriadoc.brandybuck@buckland.example')
  const kty = epk.get(1)
  expect(kty).toBe(2) // kty : EC2
  const crv = epk.get(-1) //
  expect(crv).toBe(1) // crv : P-256
  const decodedRecipientProtectedHeader = transmute.cbor.decodeFirstSync(recipientProtectedHeader);
  expect(decodedRecipientProtectedHeader.get(1)).toBe(-29) // alg : ECDH-ES + A128KW
  const decrypted = await transmute.decrypt.wrap({
    ciphertext: Buffer.from(example.output.cbor, 'hex'),
    recipients: {
      keys: [{
        "kty": "EC",
        "kid": "meriadoc.brandybuck@buckland.example",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(Buffer.from(decrypted).toString()).toBe('This is the content.')

})

it('direct', async () => {
  const protectedHeader = new Map<number, any>([
    [1, 1], // alg : A128GCM
  ])
  const unprotectedHeader = new Map<number, any>([])
  const plaintext = new TextEncoder().encode("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  const ct = await transmute.encrypt.direct({
    protectedHeader,
    unprotectedHeader,
    plaintext,
    recipients: {
      keys: [{
        "kty": "EC",
        "kid": "meriadoc.brandybuck@buckland.example",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        // encrypt to public keys only
        // "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  const decoded = transmute.cbor.decodeFirstSync(ct);
  expect(decoded.tag).toBe(96)
  const decrypted = await transmute.decrypt.direct({
    ciphertext: ct,
    recipients: {
      keys: [{
        "kty": "EC",
        "kid": "meriadoc.brandybuck@buckland.example",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(new TextDecoder().decode(decrypted)).toBe("💀 My lungs taste the air of Time Blown past falling sands ⌛")
})