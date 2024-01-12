import { base64url } from "jose";
import { createHash } from 'crypto'
import * as cbor from 'cbor-web'


const urnPrefix = `urn:ietf:params:scitt`
const nodeCryptoHashFunction = 'sha256'
const mandatoryBaseEncoding = `base64url` // no pad .

// https://www.iana.org/assignments/named-information/named-information.xhtml
const nodeCryptoToIanaNamedHashFunctions = {
  [nodeCryptoHashFunction]: 'sha-256'
}

// TODO:
// Update to align with the TBS requirement in 
// https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/pull/145

describe('should produce a SCITT URN for SCITT Messages', () => {
  it('should produce a statement identifier', () => {
    // in SCITT, statements are opaque bytes of a known content type
    // for example some bytes of type application/json
    const messageType = 'statement';
    const statement = JSON.stringify({ hello: ['world'] })
    const statementHashBase64 = base64url.encode(createHash(nodeCryptoHashFunction).update(statement).digest());
    const statementId = `${urnPrefix}:${messageType}:${nodeCryptoToIanaNamedHashFunctions[nodeCryptoHashFunction]}:${mandatoryBaseEncoding}:${statementHashBase64}`
    expect(statementId).toBe('urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1SSUUjEUp73DdHUmHnh5uX0g97fHqnGmr1o')
  })

  it('should produce a signed statement identifier', () => {
    // in SCITT, signed statements are cose sign 1 bytes of type application/cose
    // for the sake of this example, we substitute a simple cbor encoding for a cose sign 1.
    const messageType = 'signed-statement';
    const signedStatement = cbor.encode({ hello: ['world'] }) // normally this would be a valid cose sign 1 
    // (including whatever mutable values are present in the unprotected header)
    const signedStatementHashBase64 = base64url.encode(createHash(nodeCryptoHashFunction).update(signedStatement).digest());
    const signedStatementId = `${urnPrefix}:${messageType}:${nodeCryptoToIanaNamedHashFunctions[nodeCryptoHashFunction]}:${mandatoryBaseEncoding}:${signedStatementHashBase64}`
    expect(signedStatementId).toBe('urn:ietf:params:scitt:signed-statement:sha-256:base64url:h2drlVUvxYy5v9urLj7KGqBhGaaXS3Mf7K2P2us9d0U')
    // note that when receipts are added to the unprotected header, the content identifier automatically changes to reflect their presence
    // this also applies to all additional values added to the unprotected header before the identifier is computed.
    // in this way, we may say that this identifier scheme is for a "transparent statement" of "unbounded transparency"
    // we cannot know from the identifier itself, how many receipts will be present in the dereferenced content, but we do know
    // the content type for the dereferenced bytes will always be application/cose.
  })

  it('should produce a receipt identifier', () => {
    // in SCITT, receipts are cose sign 1 bytes of type application/cose
    // for the sake of this example, we substitute a simple cbor encoding for a cose sign 1.
    const messageType = 'receipt';
    const receipt = cbor.encode({ hello: ['world'], other_identifiers: ['a', 'b'] }) // normally this would be a valid cose sign 1 
    // (including whatever mutable values are present in the unprotected header)
    const receiptHashBase64 = base64url.encode(createHash(nodeCryptoHashFunction).update(receipt).digest());
    const receiptId = `${urnPrefix}:${messageType}:${nodeCryptoToIanaNamedHashFunctions[nodeCryptoHashFunction]}:${mandatoryBaseEncoding}:${receiptHashBase64}`
    expect(receiptId).toBe('urn:ietf:params:scitt:receipt:sha-256:base64url:S10jY1p6CRl8Vu8tr_S5z4tpKdvhLf0AfkbA3c2o790')
    // note that when additional proofs are added to the unprotected header, the content identifier automatically changes to reflect their presence
    // this also applies to all additional values added to the unprotected header before the identifier is computed.

    // this identifier is committing to the protected and unprotected header parameters, in addition to the signature
    // this means if the receipt expires, the identifier expires
    // this also means that if the receipt contains references to other identifiers, changing them will change its identifier.
    // a common scenario we assume is that a receipt will refer to identifiers for other receipts
    // this will build a DAG (directed acyclic graph), that is walkable assuming the following interface is implemented (regardless of API implementation details)

    // receipt = dereference(receiptId)
    // nodes = [receiptId] for each dereferencable receipt
    // edges = [receiptId, nestedReceiptId] for each nested receipt

    // because content identifiers are always computed from content, the content can never contain a reference to itself.
  })
})

describe('should produce a URL from a SCITT URN', () => {
  // in SCITT, we do not assume or require HTTP or other specific URL schemes
  // however we do provide 2 concrete examples or URLs for scitt messages.
  it('SCITT Data URLs', () => {
    // given some bytes and a content type
    // the SCITT data URL is the trivial data URL of the form
    const contentType = `application/cose`
    const receipt = cbor.encode({ hello: ['world'], other_identifiers: ['a', 'b'] }) // normally this would be a valid cose sign 1
    const baseEncodedReceipt = Buffer.from(receipt).toString('base64')
    const dataURL = `data:${contentType};base64,${baseEncodedReceipt}`;
    // note that base64 is not the same as base64url no pad.
    expect(dataURL).toBe('data:application/cose;base64,omVoZWxsb4Fld29ybGRxb3RoZXJfaWRlbnRpZmllcnOCYWFhYg==')
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

// SCITT does not require Text Encoded Identifiers (URLs or URNs)
// Binary Encoded Identifiers for URLs or URNs
// MAY be constructed according to __RFC__.
// SCRAPI does not define http interfaces for working with binary identifiers.
