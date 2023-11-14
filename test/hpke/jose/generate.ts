import crypto from 'crypto'
import * as jose from 'jose'
import { AeadId, KdfId, KemId, CipherSuite, } from 'hpke-js'
// eslint-disable-next-line @typescript-eslint/no-var-requires

type Suite0 = `HPKE-Base-P256-SHA256-AES128GCM`
const Suite0 = 'HPKE-Base-P256-SHA256-AES128GCM' as Suite0 // aka APPLE-HPKE-v1

type Suite0CurveName = `P-256`

type SuiteNames = Suite0
type CurveNames = Suite0CurveName

const algToCrv = {
  [Suite0]: 'P-256',
} as Record<SuiteNames, CurveNames>

const generate = async (alg: Suite0) => {
  const { publicKey, privateKey } = await jose.generateKeyPair(
    'ECDH-ES+A128KW',
    { extractable: true, crv: algToCrv[alg] },
  )
  const publicKeyJwk = await jose.exportJWK(publicKey)
  const privateKeyJwk = await jose.exportJWK(privateKey)
  const kid = `test-key-42`
  return {
    publicKeyJwk: {
      kty: publicKeyJwk.kty,
      crv: publicKeyJwk.crv,
      alg,
      kid,
      x: publicKeyJwk.x,
      y: publicKeyJwk.y,
      use: 'enc',
      key_ops: ['deriveBits'],
    },
    privateKeyJwk: {
      kty: privateKeyJwk.kty,
      crv: privateKeyJwk.crv,
      alg,
      kid,
      x: privateKeyJwk.x,
      y: privateKeyJwk.y,
      d: privateKeyJwk.d,
      key_ops: ['deriveBits'],
    },
  }
}

export default generate