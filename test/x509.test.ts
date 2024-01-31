import moment from 'moment'

import * as transmute from '../src'

it('sign and verify with x5t and key resolver', async () => {
  const cert = await transmute.certificate.root({
    alg: 'ES256',
    iss: 'vendor.example',
    sub: 'vendor.example',
    nbf: moment().toISOString(), // now
    exp: moment().add(5, 'minutes').toISOString() // in 5 minutes
  })
  // {
  //   "public": "-----BEGIN CERTIFICATE-----\nMIIBSDC...t4fdL0yLEskA7M=\n-----END CERTIFICATE-----",
  //   "private": "-----BEGIN PRIVATE KEY-----\nMIGHAg...n0DRu9rnbKW\n-----END PRIVATE KEY-----\n"
  // }
  const rootCertificateThumbprint = await transmute.certificate.thumbprint(cert.public)
  const signer = await transmute.certificate.signer({ alg: -7, privateKeyPKCS8: cert.private })
  const message = '💣 test ✨ mesage 🔥'
  const payload = new TextEncoder().encode(message)
  const coseSign1 = await signer.sign({
    protectedHeader: new Map<number, any>([
      [1, -7],  // alg ES256
      [34, rootCertificateThumbprint] // xt5 thumbprint
    ]),
    unprotectedHeader: new Map(),
    payload
  })
  const certificateFromThumbprint = async (x5t: [number, ArrayBuffer]): Promise<string> => {
    const [alg, hash] = x5t;
    // normally this would be a trust store lookup
    if (alg === rootCertificateThumbprint[0]) {
      if (Buffer.from(hash).toString('hex') === Buffer.from(rootCertificateThumbprint[1]).toString('hex')) {
        return cert.public
      }
    }
    throw new Error('Certificate is not trusted.')
  }
  const verifier = transmute.certificate.verifier({
    resolve: certificateFromThumbprint
  })
  const verified = await verifier.verify({ coseSign1, payload })
  expect(new TextDecoder().decode(verified)).toBe(message)
})