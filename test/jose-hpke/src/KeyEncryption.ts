import crypto from 'crypto';
import { base64url } from "jose";

import { publicKeyFromJwk, privateKeyFromJwk, HPKERecipient, isKeyAlgorithmSupported, suites, JOSE_HPKE_ALG, JWKS, formatJWK } from "./keys";

import * as mixed from './mixed'

import * as jose from 'jose'

export type RequestGeneralEncrypt = {
  protectedHeader: { enc: 'A128GCM' }
  plaintext: Uint8Array
  additionalAuthenticatedData?: Uint8Array
  recipients: JWKS
}

const sortJsonSerialization = (jwe: any)=> {
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
  const { protected: protectedHeader, unprotected, header, encrypted_key, ciphertext, iv, aad, tag, recipients} = jwe
  return JSON.parse(JSON.stringify({
    protected: protectedHeader, 
    unprotected,
    header,
    encrypted_key,
    iv,
    ciphertext, 
    tag, 
    aad,
    recipients, 
  }))
}

const prepareAad = (protectedHeader: any, aad?: Uint8Array) => {
  let textAad = base64url.encode(JSON.stringify(protectedHeader))
  if (aad){
    textAad += '.' + base64url.encode(aad)
  }
  return textAad

}

export const encrypt = async (
  req: RequestGeneralEncrypt,
  options = {serialization: 'GeneralJson'}
): Promise<any> => {

  let jwe = {} as any;
  const unprotectedHeader = {
    recipients: [] as HPKERecipient[]
  }
  let protectedHeader = base64url.encode(JSON.stringify(req.protectedHeader))
  jwe.protected = protectedHeader

  let jweAad = prepareAad(req.protectedHeader, req.additionalAuthenticatedData)

   // generate a content encryption key for a content encryption algorithm
   const contentEncryptionKey = crypto.randomBytes(16); // for A128GCM

  for (const recipient of req.recipients.keys) {
    if (isKeyAlgorithmSupported(recipient)) {
      const suite = suites[recipient.alg as JOSE_HPKE_ALG]
      // prepare the hpke sender
      const sender = await suite.createSenderContext({
        recipientPublicKey: await publicKeyFromJwk(recipient),
      });
      // encode the encapsulated key for the recipient
      const encapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
      // prepare the add for the seal operation for the recipient
      // ensure the recipient must process the protected header
      // and understand the chosen "encyption algorithm"
  
      if (req.recipients.keys.length === 1){
        let newHeader = {...req.protectedHeader, epk: {kty: 'EK', ek: encapsulatedKey}}
        jwe.protected = base64url.encode(JSON.stringify(newHeader))
        jweAad = prepareAad(newHeader, req.additionalAuthenticatedData)
      }
      
      const hpkeSealAad = new TextEncoder().encode(jweAad)
      // encrypt the content encryption key to the recipient, 
      // while binding the content encryption algorithm to the protected header
      const encrypted_key = base64url.encode(new Uint8Array(await sender.seal(contentEncryptionKey, hpkeSealAad)));
      jwe.encrypted_key = encrypted_key
      if (req.recipients.keys.length !== 1){
        unprotectedHeader.recipients.push(
          {
            encrypted_key: encrypted_key,
            header: {
              kid: recipient.kid,
              alg: recipient.alg,
              epk: {kty: 'EK', ek: encapsulatedKey} as any,
            } as any
          }
        )
      }
      
    } else if (recipient.alg === 'ECDH-ES+A128KW') {
      // throw new Error('Mixed mode not supported')
      const ek = await jose.generateKeyPair(recipient.alg, { crv: recipient.crv, extractable: true })
      const epk = await jose.exportJWK(ek.publicKey)
      const sharedSecret = await mixed.deriveKey( recipient, await jose.exportJWK(ek.privateKey))
      const encrypted_key = mixed.wrap('A128KW', sharedSecret, contentEncryptionKey)
      unprotectedHeader.recipients.push({
        encrypted_key: base64url.encode(encrypted_key),
        header: {
          kid: recipient.kid,
          alg: recipient.alg,
          epk: formatJWK(epk)
        }
      } as any)
    } else {
      throw new Error('Public key algorithm not supported: ' + recipient.alg)
    }

  }
 
  // generate an initialization vector for use with the content encryption key
  const initializationVector = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  const iv = base64url.encode(initializationVector)


  // encrypt the plaintext with the content encryption algorithm


  const encryption = await mixed.gcmEncrypt(
    req.protectedHeader.enc,
    req.plaintext,
    contentEncryptionKey,
    initializationVector,
    new TextEncoder().encode(jweAad),
  )

  const ciphertext = base64url.encode(encryption.ciphertext)
  const tag = base64url.encode(encryption.tag)
  jwe.ciphertext = ciphertext;
  jwe.iv = iv;
  jwe.tag = tag;
  // for each recipient public key, encrypt the content encryption key to the recipient public key
  // and add the result to the unprotected header recipients property
 
  jwe.recipients = unprotectedHeader.recipients
  if (jwe.recipients.length === 0){
    jwe.recipients = undefined
  }

  if (req.additionalAuthenticatedData) {
    jwe.aad = base64url.encode(req.additionalAuthenticatedData)
  }

  const general =  sortJsonSerialization(jwe);
  if (options.serialization === 'GeneralJson'){
    return general
  }
  if (options.serialization === 'Compact'){
    if (general.recipients !== undefined){
      throw new Error('Compact serialization does not support multiple recipients')
    }
    const compact = `${general.protected}.${general.encrypted_key}.${general.iv}.${general.ciphertext}.${general.tag}`
    return compact
  }

  throw new Error('Unsupported serialization')
}

export type RequestGeneralDecrypt = {
  jwe: string | any, // need types
  privateKeys: JWKS
}


const produceDecryptionResult = async (protectedHeader: string, ciphertext: string, tag: string, iv: string, cek: Uint8Array, aad ?: string) => {
  const ct = base64url.decode(ciphertext)
  const initializationVector = base64url.decode(iv);
  const parsedProtectedHeader = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)))

  let jweAad = protectedHeader
  if (aad){
    jweAad += '.' + aad
  }

  const plaintext = await mixed.gcmDecrypt(
    parsedProtectedHeader.enc, 
    cek, 
    ct, 
    initializationVector, 
    base64url.decode(tag), 
    new TextEncoder().encode(jweAad), 
  )
  const decryption = { plaintext: new Uint8Array(plaintext) } as any;
  decryption.protectedHeader = parsedProtectedHeader;
  if (aad){
    decryption.aad = base64url.decode(aad);
  }
  return decryption
}

export const decrypt = async (req: RequestGeneralDecrypt, options = {serialization: 'GeneralJson'}): Promise<any> => {
  let { protected: protectedHeader, recipients, iv, ciphertext, aad, tag } = {} as any
  let encrypted_key;
  if (options.serialization === 'GeneralJson'){
    if (typeof req.jwe !== 'object'){
        throw new Error('GeneralJson decrypt requires jwe as object')
    }
    ({ protected: protectedHeader, encrypted_key, recipients, iv, ciphertext, aad, tag } = req.jwe);
  }

  if (recipients === undefined && options.serialization !== 'Compact' && typeof req.jwe !== 'string'){
    if (req.privateKeys.keys.length !== 1){
      throw new Error('Expected single private key for single recipient general json')
    }
    const parsedProtectedHeader = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)))
    recipients = [
      {
        encrypted_key,
        header: {
          kid: req.privateKeys.keys[0].kid,
          alg: req.privateKeys.keys[0].alg,
          epk: parsedProtectedHeader.epk
        }
      }
    ]
  }

  if (options.serialization === 'Compact'){
    if (typeof req.jwe === 'object'){
        throw new Error('Compact decrypt requires jwe as string')
    }
    ([protectedHeader, encrypted_key, iv, ciphertext, tag] = req.jwe.split('.'))
    const parsedProtectedHeader = JSON.parse(new TextDecoder().decode(base64url.decode(protectedHeader)))
    recipients = [
      {
        encrypted_key,
        header: {
          kid: req.privateKeys.keys[0].kid,
          alg: req.privateKeys.keys[0].alg,
          epk: parsedProtectedHeader.epk
        }
      }
    ]
  }
 
  // find a recipient for which we have a private key
  let matchingRecipient = undefined
  let matchingPrivateKey = undefined
  for (const privateKey of req.privateKeys.keys) {
    const recipient = recipients.find((r: HPKERecipient) => {
      return r.header.kid === privateKey.kid
    })
    if (recipient) {
      // we have a private key for this recipient
      matchingRecipient = recipient;
      matchingPrivateKey = privateKey;
      break
    }
  }

  if (!matchingRecipient || !matchingPrivateKey) {
    throw new Error('No decryption key found for the given recipients')
  }

  if (isKeyAlgorithmSupported(matchingPrivateKey)) {
    // We could check here to see if the "enc" in the protected header
    // matches the last part of the "alg" on the private key.

    const suite = suites[matchingPrivateKey.alg as JOSE_HPKE_ALG]

    // selected the encapsulated_key for the recipient
    const { encrypted_key, header } = matchingRecipient;
    const { epk: {ek: encapsulated_key} } = header

    // create the HPKE recipient
    const recipient = await suite.createRecipientContext({
      recipientKey: await privateKeyFromJwk(matchingPrivateKey),
      enc: base64url.decode(encapsulated_key)
    })

    // compute the additional data from the protected header
    let jweAad = protectedHeader
    if (aad){
      jweAad += '.' + aad
    }
    const hpkeOpenAad = new TextEncoder().encode(jweAad)

    // open the content encryption key for the given content encryption algorithm
    // which is described in the protected header
    const contentEncryptionKey = new Uint8Array(await recipient.open(base64url.decode(encrypted_key), hpkeOpenAad))

    // determine the content encryption algorithm
    // now that we know we have a key that supports it
    return produceDecryptionResult(protectedHeader, ciphertext, tag, iv, contentEncryptionKey, aad);
  } else if (matchingPrivateKey.alg === 'ECDH-ES+A128KW') {
    // compute the shared secret from the recipient
    const sharedSecret = await mixed.deriveKey( matchingRecipient.header.epk, matchingPrivateKey)
    const encryptedKey = jose.base64url.decode(matchingRecipient.encrypted_key)
    // unrwap the content encryption key
    const contentEncryptionKey = mixed.unwrap('A128KW', sharedSecret, encryptedKey)
    // the test is the same for both HPKE-Base-P256-SHA256-AES128GCM and ECDH-ES+A128KW with A128GCM
    return produceDecryptionResult(protectedHeader, ciphertext, tag, iv, contentEncryptionKey, aad);
  } else {
    throw new Error('Private key algorithm not supported.')
  }

}