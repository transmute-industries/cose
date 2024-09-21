import fs from 'fs'
import moment from 'moment'
import * as jose from 'jose'
import * as cose from '../src'
import { labels_to_algorithms } from '../src/iana/requested/cose'

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
    alg: cose.algorithm.es256,
    privateKeyPKCS8: cert.private
  })
  const content = fs.readFileSync('./examples/image.png')
  const coseSign1 = await signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.alg, cose.algorithm.es256],  // alg ES256
      [cose.header.x5t, rootCertificateThumbprint], // xt5 thumbprint
      [cose.header.content_type, "image/png"], // content_type image/png
    ]),
    payload: content
  })
  const certificateFromThumbprint = async (coseSign1: cose.CoseSign1Bytes): Promise<cose.PublicKeyJwk> => {
    const { tag, value } = cose.cbor.decodeFirstSync(coseSign1)
    if (tag !== cose.tag.COSE_Sign1) {
      throw new Error('Only tagged cose sign 1 are supported')
    }
    const [protectedHeaderBytes] = value;
    const protectedHeaderMap = cose.cbor.decodeFirstSync(protectedHeaderBytes)
    const alg = protectedHeaderMap.get(cose.header.alg)
    const x5t = protectedHeaderMap.get(cose.header.x5t) // get x5t
    if (!x5t) {
      throw new Error('x5t is required in protected header to use the certificate verifer exposed by this library')
    }
    const [hashAlgorith, hash] = x5t;
    // normally this would be a trust store lookup
    if (hashAlgorith === rootCertificateThumbprint[0]) {
      if (Buffer.from(hash).toString('hex') === Buffer.from(rootCertificateThumbprint[1]).toString('hex')) {
        const algName = labels_to_algorithms.get(alg) as any
        // could do extra certificate policy validation here...
        const publicKeyJwk = await jose.exportJWK(await jose.importX509(cert.public, algName))
        publicKeyJwk.alg = algName
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