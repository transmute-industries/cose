
import * as jose from '../jose-hpke'

import * as cose from '../../src'

it('generate private keys', async () => {
  const k1 = await jose.key.generate('HPKE-Base-P256-SHA256-AES128GCM')
  const k2 = await cose.key.generate('HPKE-Base-P256-SHA256-AES128GCM', 'application/cose-key')
})
