import signer from './signer'
import verifier from './verifier'
import diagnostic from './diagnostic'
import unprotectedHeader from './unprotectedHeader'
import merkle from './merkle'
import cbor from './cbor'
import detachPayload from './detachPayload'
import attachPayload from './attachPayload'

const cose = {
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
