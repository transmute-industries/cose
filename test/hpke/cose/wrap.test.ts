
import generate from '../jose/generate'
import wrap from './wrap'
import * as coseKey from '../../../src/key'
import { Suite0 } from '../common'

it('sanity', async () => {
  const k = await generate(Suite0)
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const k2 = {
    cosePublicKey: coseKey.importJWK(k.publicKeyJwk),
    cosePrivateKey: coseKey.importJWK(k.privateKeyJwk)
  }
  const c4 = await wrap.encrypt(m, k2.cosePublicKey)
  const d4 = await wrap.decrypt(c4, k2.cosePrivateKey)
  const rpt4 = new TextDecoder().decode(d4)
  expect(rpt4).toBe(pt)
})