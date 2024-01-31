import fs from 'fs'
import moment from 'moment'
import * as jose from 'jose'
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
  const content = fs.readFileSync('./examples/image.png')
  const coseSign1 = await signer.sign({
    protectedHeader: new Map<number, any>([
      [1, -7],  // alg ES256
      [34, rootCertificateThumbprint], // xt5 thumbprint
      [3, "image/png"], // content_type image/png
    ]),
    unprotectedHeader: new Map(),
    payload: content
  })
  const certificateFromThumbprint = async (protectedHeaderMap: transmute.ProtectedHeaderMap): Promise<transmute.PublicKeyJwk> => {

    const alg = protectedHeaderMap.get(1)
    const x5t = protectedHeaderMap.get(34) // get x5t
    if (!x5t) {
      throw new Error('x5t is required in protected header to use the certificate verifer exposed by this library')
    }
    const [hashAlgorith, hash] = x5t;
    // normally this would be a trust store lookup
    if (hashAlgorith === rootCertificateThumbprint[0]) {
      if (Buffer.from(hash).toString('hex') === Buffer.from(rootCertificateThumbprint[1]).toString('hex')) {
        const foundAlgorithm = Object.values(transmute.IANACOSEAlgorithms).find((entry) => {
          return entry.Value === `${alg}`
        })
        if (!foundAlgorithm) {
          throw new Error('Could not find algorithm in registry for: ' + alg)
        }
        // could do extra certificate policy validation here...
        const publicKeyJwk = await jose.exportJWK(await jose.importX509(cert.public, foundAlgorithm.Name))
        publicKeyJwk.alg = foundAlgorithm.Name
        return publicKeyJwk
      }
    }
    throw new Error('Certificate is not trusted.')
  }
  const verifier = transmute.certificate.verifier({
    resolve: certificateFromThumbprint
  })
  const verified = await verifier.verify({ coseSign1, payload: content })
  // faster to compare hex strings.
  expect(Buffer.from(verified).toString('hex')).toEqual(content.toString('hex'))

  // fs.writeFileSync('./examples/image.x5t.signature.cbor', coseSign1)
  // fs.writeFileSync('./examples/image.x5t.public-key.crt', cert.public)
  // fs.writeFileSync('./examples/cert.private.pem', cert.private)
})