
import generate from '../jose/generate'
import direct from './direct'
import * as coseKey from '../../../src/key'
import alternateDiagnostic from '../../../src/diagnostic'

import { Suite0 } from '../common'

it('sanity', async () => {
  const k = await generate(Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const k2 = {
    cosePublicKey: coseKey.importJWK(k.publicKeyJwk),
    cosePrivateKey: coseKey.importJWK(k.privateKeyJwk)
  }
  k2.cosePublicKey.set(2, 'recipient-key-0')
  const c3 = await direct.encrypt(m, k2.cosePublicKey)
  const c3Diagnostic = await alternateDiagnostic(c3)
  // console.log('/ COSE HPKE Direct /\n' + c3Diagnostic)
  expect(c3Diagnostic.startsWith('96([')).toBe(true)
  // Compare to direct mode ecdh
  // https://github.com/cose-wg/Examples/blob/3221310e2cf50ad13213daa7ca278209a8bc85fd/ecdh-direct-examples/p256-hkdf-256-01.json
  const d3 = await direct.decrypt(c3, k2.cosePrivateKey)
  const rpt3 = new TextDecoder().decode(d3)
  expect(rpt3).toBe(pt)
})