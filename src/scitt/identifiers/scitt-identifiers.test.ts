

import cose from '../../../src'

let signedStatement: Buffer;
let receipt: Buffer;

beforeAll(async () => {
  const protectedHeader = new Map();
  protectedHeader.set(1, -7)
  const unprotectedHeader = new Map();
  const signer = cose.lib.signer({
    secretKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      d: 'o_95vWSheg19YU7viU3PmW_kRIWk14HiVLXDXiZjEL0',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    }
  });
  signedStatement = await signer.sign({ protectedHeader, unprotectedHeader, payload: Buffer.from('fake signed statement') });
  receipt = await signer.sign({ protectedHeader, unprotectedHeader, payload: Buffer.from('fake receipt') });
})

describe('should produce a SCITT URN for SCITT Messages', () => {

  it('should produce a statement identifier', () => {
    // in SCITT, statements are opaque bytes of a known content type
    // for example some bytes of type application/json
    const statement = JSON.stringify({ hello: ['world'] })
    const statementId = cose.scitt.identifiers.urn('statement', Buffer.from(statement))
    expect(statementId).toBe('urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1SSUUjEUp73DdHUmHnh5uX0g97fHqnGmr1o')
  })

  it('should produce a signed statement identifier', () => {
    // in SCITT, signed statements are cose sign 1 bytes of type application/cose
    const signedStatementId = cose.scitt.identifiers.urn('signed-statement', signedStatement)
    // urn:ietf:params:scitt:signed-statement:sha-256:base64url:ysBmsRG2DagHYCgQuGHsG9alWWIiRwVRUhAz8j8cMxM
    expect(signedStatementId.startsWith('urn:ietf:params:scitt:signed-statement:sha-256:base64url:')).toBe(true)
  })

  it('should produce a receipt identifier', () => {
    // in SCITT, receipts are cose sign 1 bytes of type application/cose
    // in SCITT, signed statements are cose sign 1 bytes of type application/cose
    const receiptId = cose.scitt.identifiers.urn('receipt', receipt)
    // urn:ietf:params:scitt:receipt:sha-256:base64url:ysBmsRG2DagHYCgQuGHsG9alWWIiRwVRUhAz8j8cMxM
    expect(receiptId.startsWith('urn:ietf:params:scitt:receipt:sha-256:base64url:')).toBe(true)
  })
})

describe('should produce a URL from a SCITT URN', () => {
  // in SCITT, we do not assume or require HTTP or other specific URL schemes
  // however we do provide 2 concrete examples or URLs for scitt messages.
  it('SCITT Data URLs', () => {
    // given some bytes and a content type
    // the SCITT data URL is the trivial data URL of the form
    const contentType = `application/cose`
    const baseEncodedReceipt = Buffer.from(receipt).toString('base64')
    const dataURL = `data:${contentType};base64,${baseEncodedReceipt}`;
    // note that base64 is not the same as base64url no pad.
    expect(dataURL.startsWith('data:application/cose;base64,')).toBe(true)
  })
  it('SCITT SCRAPI URLs', () => {
    // SCRAPI provides an optional to implement HTTP API that supports the required dereference operation necessary to compute the dag
    // in SCRAPI dereference is implemented by the concrete HTTP resolve operation for a SCITT SCRAPI URL
    // SCITT SCRAPI URLs are constructed from SCITT URNs
    const transparencyServiceApiBase = `https://transparency.example/api/identifiers/`
    const exampleReceiptUrn = 'urn:ietf:params:scitt:receipt:sha-256:base64url:S10jY1p6CRl8Vu8tr_S5z4tpKdvhLf0AfkbA3c2o790'
    const scittScrapiReceiptUrl = `${transparencyServiceApiBase}${exampleReceiptUrn}`
    expect(scittScrapiReceiptUrl).toBe('https://transparency.example/api/identifiers/urn:ietf:params:scitt:receipt:sha-256:base64url:S10jY1p6CRl8Vu8tr_S5z4tpKdvhLf0AfkbA3c2o790')

    // SCRAPI URLs support content negotiation via the Accept and Content-Type http headers.
    // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept

    // Implementations MAY choose to return content types that wrap SCITT Message content types
    // For example returning application/json or application/vnd.cool-api+json
    // Which encodes application/cose messages as data URLs
    // Returning wrapper encodings of scitt messages from SCRAPI that are not well formed data URLs is NOT RECOMMENDED.
    // For example, it is not recommended to return custom base encodings that destructure scitt data URLs.
  })
})

