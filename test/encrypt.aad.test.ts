
import * as cose from '../src'

const {
  ProtectedHeader,
  UnprotectedHeader,
  Protected,
  Aead,
  COSE_Encrypt,
  Direct,
  encrypt, decrypt
} = cose


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

const message = "💀 My lungs taste the air of Time Blown past falling sands ⌛"
const aad = new TextEncoder().encode('🍃 If there is no struggle, there is no progress.')
const plaintext = new TextEncoder().encode(message)

it('wrap with external aad', async () => {
  const ciphertext = await encrypt.wrap({
    aad,
    protectedHeader: ProtectedHeader([
      [Protected.Alg, Aead.A128GCM],
    ]),
    plaintext,
    recipients: encryptionKeys
  })
  const decrypted = await decrypt.wrap({
    aad,
    ciphertext: ciphertext,
    recipients: decryptionKeys
  })
  expect(new TextDecoder().decode(decrypted)).toBe(message)
})


it('direct', async () => {
  const ciphertext = await encrypt.direct({
    aad,
    protectedHeader: ProtectedHeader([
      [Protected.Alg, Direct['HPKE-Base-P256-SHA256-AES128GCM']],
    ]),
    plaintext,
    recipients: encryptionKeys
  })
  const decrypted = await decrypt.direct({
    aad,
    ciphertext,
    recipients: decryptionKeys
  })
  expect(new TextDecoder().decode(decrypted)).toBe(message)
})
