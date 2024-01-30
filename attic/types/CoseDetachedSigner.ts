import { ProtectedHeader } from './ProtectedHeader'
import { UnprotectedHeader } from './UnprotectedHeader'
import { Payload } from './Payload'
import { DetachedSignature } from './DetachedSignature'

export type CoseDetachedSigner = {
  alg: 'ES256' | 'ES384' | 'ES512' | 'EdDSA' | 'ES256K' | string
  sign: (request: {
    protectedHeader: ProtectedHeader
    unprotectedHeader?: UnprotectedHeader
    payload: Payload
  }) => Promise<DetachedSignature>
}
