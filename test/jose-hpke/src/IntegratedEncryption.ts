import { base64url } from "jose";

import { publicKeyFromJwk, suites, isKeyAlgorithmSupported, privateKeyFromJwk, JOSE_HPKE_ALG } from "./keys";



const createJWEAAD = (protectedHeader: string, aad?: Uint8Array) => {
  let textAad = protectedHeader
  if (aad && aad.length > 0) {
    textAad += '.' + base64url.encode(aad)
  }
  return textAad
}

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any, aad = new Uint8Array(), options = { serialization: 'CompactSerialization' }): Promise<string | any> => {
  if (!isKeyAlgorithmSupported(publicKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[publicKeyJwk.alg as JOSE_HPKE_ALG]
  const sender = await suite.createSenderContext({
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  });

  const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const protectedHeader = base64url.encode(JSON.stringify({
    alg: "dir",
    enc: publicKeyJwk.alg,
    "epk": {
      "kty": "EK",
      "ek": encapsulatedKey
    }
  }))

  const jweAad = createJWEAAD(protectedHeader, aad)

  const hpkeSealAad = new TextEncoder().encode(jweAad)
  const ciphertext = base64url.encode(new Uint8Array(await sender.seal(plaintext, hpkeSealAad)));
  const [encodedProtectedHeader, encodedAAD] = jweAad.split('.')

  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
  const compact = `${encodedProtectedHeader}...${ciphertext}.`
  if (options.serialization === 'CompactSerialization') {
    if (aad && aad.length > 2) {
      throw new Error('CompactSerialization does not support JWE AAD')
    }
    return compact
  }
  if (options.serialization === 'GeneralJson') {
    const [protectedHeader, encryptedKey, initializationVector, ciphertext, tag] = compact.split('.')
    return JSON.parse(JSON.stringify({
      protected: protectedHeader,
      encrypted_key: encryptedKey.length === 0 ? undefined : encryptedKey,
      iv: initializationVector.length === 0 ? undefined : initializationVector,
      tag: tag.length === 0 ? undefined : tag,
      aad: encodedAAD,
      ciphertext: ciphertext.length === 0 ? undefined : ciphertext
    }))
  }
  throw new Error('Unsupported Serialization.')
}

export const decrypt = async (jwe: string | any, privateKeyJwk: any, options = { serialization: 'CompactSerialization' }): Promise<any> => {
  if (typeof jwe === 'object' && options.serialization !== 'GeneralJson') {
    throw new Error('expected object for general json serialization decrypt.')
  }

  let protectedHeader
  let ciphertext
  let aad;
  let _blankEncKey
  let _blankIv
  let _blankTag
  if (options.serialization === 'CompactSerialization') {
    if (typeof jwe !== 'string') {
      throw new Error('expected string for compact serialization decrypt.')
    }

    ([protectedHeader, _blankEncKey, _blankIv, ciphertext, _blankTag] = jwe.split('.'));
  }
  if (options.serialization === 'GeneralJson') {
    if (typeof jwe !== 'object') {
      throw new Error('expected object for general json serialization decrypt.')
    }

    ({ protected: protectedHeader, aad, ciphertext } = jwe)
  }
  if (!isKeyAlgorithmSupported(privateKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[privateKeyJwk.alg as JOSE_HPKE_ALG]

  const decodedProtectedHeader = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)))
  if (decodedProtectedHeader.alg !== 'dir') {
    throw new Error('Expected alg:dir for integrated encryption.')
  }
  if (decodedProtectedHeader.enc !== privateKeyJwk.alg) {
    throw new Error('Private key does not support this algorithm: ' + decodedProtectedHeader.enc)
  }
  const recipient = await suite.createRecipientContext({
    recipientKey: await privateKeyFromJwk(privateKeyJwk),
    enc: base64url.decode(decodedProtectedHeader.epk.ek)
  })
  const additionalAuthenticatedData = aad ? base64url.decode(aad) : new Uint8Array()
  const jweAad = createJWEAAD(protectedHeader, additionalAuthenticatedData)
  const hpkeOpenAad = new TextEncoder().encode(jweAad)
  const plaintext = await recipient.open(base64url.decode(ciphertext), hpkeOpenAad)
  const result = { plaintext: new Uint8Array(plaintext), protectedHeader: decodedProtectedHeader } as any
  if (aad && aad.length > 0) {
    result.additionalAuthenticatedData = new Uint8Array(additionalAuthenticatedData)
  }
  return result
}