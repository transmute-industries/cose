import * as transmute from '../src'
import fs from 'fs'
import { cbor } from '@transmute/cose'

it('wrap', async () => {
  const protectedHeader = new Map<number, any>([
    [1, 1], // alg : A128GCM
  ])
  const unprotectedHeader = new Map<number, any>([])
  const plaintext = new TextEncoder().encode("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  const ct = await transmute.encrypt.wrap({
    protectedHeader,
    unprotectedHeader,
    plaintext,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
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
  const decrypted = await transmute.decrypt.wrap({
    ciphertext: ct,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(new TextDecoder().decode(decrypted)).toBe("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  fs.writeFileSync('./examples/hpke.wrap.diag', await cbor.diagnose(ct))
})


it('direct', async () => {
  const protectedHeader = new Map<number, any>([
    [1, 35], // alg : Direct || HPKE-Base-P256-SHA256-AES128GCM
  ])
  const unprotectedHeader = new Map<number, any>([])
  const plaintext = new TextEncoder().encode("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  const ct = await transmute.encrypt.direct({
    protectedHeader,
    unprotectedHeader,
    plaintext,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        // encrypt to public keys only
        // "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  const decoded = transmute.cbor.decodeFirstSync(ct);
  expect(decoded.tag).toBe(16)
  const decrypted = await transmute.decrypt.direct({
    ciphertext: ct,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(new TextDecoder().decode(decrypted)).toBe("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  fs.writeFileSync('./examples/hpke.direct.diag', await cbor.diagnose(ct))
})



it('direct with party info', async () => {
  const protectedHeader = new Map<number, any>([
    [1, 35], // alg :  HPKE-Base-P256-SHA256-AES128GCM
    [-21, Buffer.from(new TextEncoder().encode('did:example:party-u'))],
    [-24, Buffer.from(new TextEncoder().encode('did:example:party-v'))]
  ])
  const unprotectedHeader = new Map<number, any>([])
  const plaintext = new TextEncoder().encode("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  const ct = await transmute.encrypt.direct({
    protectedHeader,
    unprotectedHeader,
    plaintext,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        // encrypt to public keys only
        // "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  const decoded = transmute.cbor.decodeFirstSync(ct);
  expect(decoded.tag).toBe(16)
  const decrypted = await transmute.decrypt.direct({
    ciphertext: ct,
    recipients: {
      keys: [{
        "kid": "meriadoc.brandybuck@buckland.example",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }]
    }
  })
  expect(new TextDecoder().decode(decrypted)).toBe("💀 My lungs taste the air of Time Blown past falling sands ⌛")
  fs.writeFileSync('./examples/hpke.direct.party-id.diag', await cbor.diagnose(ct))
})