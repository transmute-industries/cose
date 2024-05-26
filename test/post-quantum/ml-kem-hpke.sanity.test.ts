
import * as cose from '../../src'

it('HPKE-Base-ML-KEM-768-SHA256-AES128GCM', async () => {
  const secretKey: cose.key.CoseKey = await cose.key.generate("HPKE-Base-ML-KEM-768-SHA256-AES128GCM")
  expect(secretKey.get(cose.Key.Type)).toBe(cose.KeyType['ML-KEM']) // requested assignment for key type ML-KEM
  expect(secretKey.get(cose.Key.Algorithm)).toBe(cose.KeyTypeAlgorithms['ML-KEM']['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']) // requested assignment for algorithm ML-KEM-768
  expect(secretKey.get(cose.KeyTypeParameters['ML-KEM'].Public)).toBeDefined() // public key parameter for key type ML-KEM
  expect(secretKey.get(cose.KeyTypeParameters['ML-KEM'].Secret)).toBeDefined() // secret or private key parameter for key type ML-KEM
  const publicKey = await cose.key.publicFromPrivate<cose.key.CoseKey>(secretKey)
  expect(publicKey.get(cose.KeyTypeParameters['ML-KEM'].Secret)).toBeUndefined() // public keys have no secret component

  const message = "💀 My lungs taste the air of Time Blown past falling sands ⌛"
  const plaintext = new TextEncoder().encode(message)
  const encryptionKeys = {
    keys: [
      await cose.key.convertCoseKeyToJsonWebKey<cose.key.JsonWebKey>(publicKey)
    ]
  }
  const ciphertext = await cose.encrypt.direct({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Direct['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']],
    ]),
    unprotectedHeader: cose.UnprotectedHeader([]),
    plaintext,
    recipients: encryptionKeys
  })

  // const ctDiag = await cose.cbor.diagnose(ciphertext)
  // console.log(ctDiag)

  const decryptionKeys = {
    keys: [
      await cose.key.convertCoseKeyToJsonWebKey<cose.key.JsonWebKey>(secretKey)
    ]
  }
  const recoveredPlaintext = await cose.decrypt.direct({
    ciphertext,
    recipients: decryptionKeys
  })
  expect(new TextDecoder().decode(recoveredPlaintext)).toBe(message)

})
