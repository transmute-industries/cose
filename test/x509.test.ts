import fs from 'fs'
import moment from 'moment'
import * as jose from 'jose'
import * as cose from '../src'

it('sign and verify with x5t and key resolver', async () => {
  const cert = await cose.certificate.root({
    alg: 'ES256',
    iss: 'vendor.example',
    sub: 'vendor.example',
    nbf: moment().toISOString(), // now
    exp: moment().add(5, 'minutes').toISOString(), // in 5 minutes
    serial: "01"
  })
  // {
  //   "public": "-----BEGIN CERTIFICATE-----\nMIIBSDC...t4fdL0yLEskA7M=\n-----END CERTIFICATE-----",
  //   "private": "-----BEGIN PRIVATE KEY-----\nMIGHAg...n0DRu9rnbKW\n-----END PRIVATE KEY-----\n"
  // }
  const rootCertificateThumbprint = await cose.certificate.thumbprint(cert.public)
  const signer = await cose.certificate.pkcs8Signer({
    alg: cose.Signature.ES256,
    privateKeyPKCS8: cert.private
  })
  const content = fs.readFileSync('./examples/image.png')
  const coseSign1 = await signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Signature.ES256],  // alg ES256
      [cose.Protected.X5t, rootCertificateThumbprint], // xt5 thumbprint
      [cose.Protected.ContentType, "image/png"], // content_type image/png
    ]),
    payload: content
  })
  const certificateFromThumbprint = async (coseSign1: cose.CoseSign1Bytes): Promise<cose.PublicKeyJwk> => {
    const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
    if (tag !== cose.COSE_Sign1) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
    const alg = protectedHeaderMap.get(cose.Protected.Alg)
    const x5t = protectedHeaderMap.get(cose.Protected.X5t) // get x5t
    if (!x5t) {
      throw new Error('x5t is required in protected header to use the certificate verifer exposed by this library')
    }
    const [hashAlgorith, hash] = x5t;
    // normally this would be a trust store lookup
    if (hashAlgorith === rootCertificateThumbprint[0]) {
      if (Buffer.from(hash).toString('hex') === Buffer.from(rootCertificateThumbprint[1]).toString('hex')) {
        const foundAlgorithm = Object.values(cose.IANACOSEAlgorithms).find((entry) => {
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
  const verifier = cose.certificate.verifier({
    resolver: {
      resolve: certificateFromThumbprint
    }
  })
  const verified = await verifier.verify({ coseSign1, payload: content })
  // faster to compare hex strings.
  expect(Buffer.from(verified).toString('hex')).toEqual(content.toString('hex'))

  // fs.writeFileSync('./examples/image.x5t.signature.cbor', coseSign1)
  // fs.writeFileSync('./examples/image.x5t.public-key.crt', cert.public)
  // fs.writeFileSync('./examples/cert.private.pem', cert.private)
})