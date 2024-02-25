import * as cose from '../src'
import fs from 'fs'

const {
  cbor,
  encrypt,
  decrypt,
  ProtectedHeader,
  UnprotectedHeader,
  Protected,
  Aead,
  COSE_Encrypt,
  COSE_Encrypt0,
  Direct
} = cose

const message = "💀 My lungs taste the air of Time Blown past falling sands ⌛"
const plaintext = new TextEncoder().encode(message)
const encryptionKeys = {
  keys: [{
    "kid": "meriadoc.brandybuck@buckland.example",
    "alg": "HPKE-Base-P256-SHA256-AES128GCM",
    "kty": "EC",
    "crv": "P-256",
    "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
    "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
  }]
}
const decryptionKeys = {
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

it('wrap', async () => {
  const ciphertext = await encrypt.wrap({
    protectedHeader: ProtectedHeader([
      [Protected.Alg, Aead.A128GCM],
    ]),
    unprotectedHeader: UnprotectedHeader([]),
    plaintext,
    recipients: encryptionKeys
  })
  const decoded = cbor.decodeFirstSync(ciphertext);
  expect(decoded.tag).toBe(COSE_Encrypt)
  const decrypted = await decrypt.wrap({
    ciphertext,
    recipients: decryptionKeys
  })
  expect(new TextDecoder().decode(decrypted)).toBe(message)
  // fs.writeFileSync('./examples/hpke.wrap.diag', await cbor.diagnose(ciphertext))
})

it('direct', async () => {
  const ciphertext = await encrypt.direct({
    protectedHeader: ProtectedHeader([
      [Protected.Alg, Direct['HPKE-Base-P256-SHA256-AES128GCM']],
    ]),
    unprotectedHeader: UnprotectedHeader([]),
    plaintext,
    recipients: encryptionKeys
  })
  const decoded = cbor.decodeFirstSync(ciphertext);
  expect(decoded.tag).toBe(COSE_Encrypt0)
  const decrypted = await decrypt.direct({
    ciphertext,
    recipients: decryptionKeys
  })
  expect(new TextDecoder().decode(decrypted)).toBe(message)
  // fs.writeFileSync('./examples/hpke.direct.diag', await cbor.diagnose(ciphertext))
})
