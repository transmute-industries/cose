
import { Suite0 } from '../common'
import generate from './generate'
import wrap from './wrap'

it('wrap', async () => {
  const k = await generate(Suite0)

  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)

  const c2 = await wrap.encrypt(m, k.publicKeyJwk)
  // console.log(JSON.stringify(c2, null, 2))
  const d2 = await wrap.decrypt(c2, k.privateKeyJwk)
  const rpt2 = new TextDecoder().decode(d2)
  expect(rpt2).toBe(pt)
})