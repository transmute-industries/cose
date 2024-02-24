
import * as transmute from '@transmute/cose'

const test = async () => {
  const k2 = await transmute.key.generate('ES256', 'application/jwk+json')
  const encoder = new TextEncoder();
  const decoder = new TextDecoder()
  const signer = transmute.detached.signer({ remote: transmute.crypto.signer({ secretKeyJwk: k2 }) })
  const message = '💣 test ✨ mesage 🔥'
  const payload = encoder.encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload
  })
  const verifier = transmute.detached.verifier({
    resolver: {
      resolve: () => {
        return transmute.key.publicFromPrivate(k2)
      }
    }
  })
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

  const protectedHeader = new Map([
    [1, 35], // alg : Direct || HPKE-Base-P256-SHA256-AES128GCM
  ])
  const unprotectedHeader = new Map([])
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
  console.log(new TextDecoder().decode(decrypted))
  console.log('test complete.');
}
// setup exports on window
window.test = {
  test
}
