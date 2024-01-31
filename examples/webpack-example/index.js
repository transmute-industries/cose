
import * as transmute from '@transmute/cose'

const test = async () => {
  const k2 = await transmute.key.generate('ES256', 'application/jwk+json')
  const encoder = new TextEncoder();
  const decoder = new TextDecoder()
  const signer = transmute.detached.signer({ secretKeyJwk: k2 })
  const message = '💣 test ✨ mesage 🔥'
  const payload = encoder.encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload
  })
  const verifier = transmute.detached.verifier({ publicKeyJwk: transmute.key.publicFromPrivate(k2) })
  const verified = await verifier.verify({ coseSign1, payload })
  console.log(decoder.decode(verified));


  const entries = await Promise.all([`💣 test`, `✨ test`, `🔥 test`]
    .map((entry) => {
      return encoder.encode(entry)
    })
    .map((entry) => {
      return transmute.receipt.leaf(entry)
    }))

  const inclusion = await transmute.receipt.inclusion.issue({
    protectedHeader: new Map([
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    entry: 1,
    entries,
    signer
  })

  const oldVerifiedRoot = await transmute.receipt.inclusion.verify({
    entry: entries[1],
    receipt: inclusion,
    verifier
  })

  entries.push(await transmute.receipt.leaf(encoder.encode('✨ new entry ✨')))

  const { root, receipt } = await transmute.receipt.consistency.issue({
    protectedHeader: new Map([
      [1, -7],  // alg ES256
      [-111, 1] // vds RFC9162
    ]),
    receipt: inclusion,
    entries,
    signer
  })
  const consistencyValidated = await transmute.receipt.consistency.verify({
    oldRoot: oldVerifiedRoot,
    newRoot: root,
    receipt: receipt,
    verifier
  })

  console.log('consistency', consistencyValidated);

  const cert = await transmute.certificate.root({
    alg: 'ES256',
    iss: 'vendor.example',
    sub: 'vendor.example',
    nbf: '2024-01-31T20:50:16.139Z',
    exp: '2124-01-31T20:50:16.139Z'
  })

  console.log(cert.public);

  console.log('test complete.');
}
// setup exports on window
window.test = {
  test
}
