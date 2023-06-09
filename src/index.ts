import signer from './signer'
import verifier from './verifier'
import diagnostic from './diagnostic'
import unprotectedHeader from './unprotectedHeader'
import merkle from './merkle'
import cbor from './cbor'
import detachPayload from './detachPayload'
import attachPayload from './attachPayload'

import detached from './detached'

import { RFC9162 } from '@transmute/rfc9162'

import getKid from './getKid'
import getContentType from './getContentType'

const cose = {
  detached,
  getKid,
  getContentType,
  binToHex: RFC9162.binToHex,
  hexToBin: RFC9162.hexToBin,
  cbor,
  merkle,
  diagnostic,
  detachPayload,
  attachPayload,
  unprotectedHeader,
  signer,
  verifier,
}

export * from './types'
export default cose
