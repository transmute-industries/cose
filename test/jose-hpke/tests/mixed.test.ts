// import fs from 'fs'

import * as hpke from '../src'

it('encrypt / decrypt', async () => {
  // recipient 1
  const privateKey1 = await hpke.key.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const publicKey1 = await hpke.key.publicFromPrivate(privateKey1)
  // recipient 2
  const privateKey2 = await hpke.key.generate('HPKE-Base-P256-SHA256-AES128GCM')
  privateKey2.alg = 'ECDH-ES+A128KW' // overwrite algorithm
  const publicKey2 = await hpke.key.publicFromPrivate(privateKey2)
  const resolvePrivateKey = (kid: string): any => {
    if (kid === publicKey1.kid) {
      return privateKey1
    }
    if (kid === publicKey2.kid) {
      return privateKey2
    }
    throw new Error('Unknown kid')
  }
  // recipients as a JWKS
  const recipientPublicKeys = {
    "keys": [
      publicKey1,
      publicKey2
    ]
  }
  const plaintext = new TextEncoder().encode(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
  const aad = new TextEncoder().encode('💀 aad')
  const contentEncryptionAlgorithm = 'A128GCM'
  const jwe = await hpke.KeyEncryption.encrypt({
    protectedHeader: { enc: contentEncryptionAlgorithm },
    plaintext,
    additionalAuthenticatedData: aad,
    recipients: recipientPublicKeys
  });
  // console.log(JSON.stringify(jwe, null, 2))
  // fs.writeFileSync('./example.jwe.json', JSON.stringify(jwe, null, 2))
  for (const recipient of recipientPublicKeys.keys) {
    const privateKey = resolvePrivateKey(recipient.kid)
    // simulate having only one of the recipient private keys
    const recipientPrivateKeys = { "keys": [privateKey] }
    const decryption = await hpke.KeyEncryption.decrypt({ jwe, privateKeys: recipientPrivateKeys })
    expect(new TextDecoder().decode(decryption.plaintext)).toBe(`It’s a 💀 dangerous business 💀, Frodo, going out your door.`);
    expect(new TextDecoder().decode(decryption.aad)).toBe('💀 aad');
  }

})