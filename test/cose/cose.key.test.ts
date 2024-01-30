
import * as transmute from '../../src'

it('generate cose key', async () => {
  const k = await transmute.key.generate('ES256', 'application/cose-key')
})