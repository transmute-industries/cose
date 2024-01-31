
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
  console.log('test complete.');
}
// setup exports on window
window.test = {
  test
}
