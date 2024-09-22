
import { crypto } from '../src'
import * as cbor from 'cbor-web'
import * as cose from '../src/iana/assignments/cose'
import * as jose from '../src/iana/assignments/jose'

describe('web key', () => {
  it('generate', async () => {
    const key = new Map(Object.entries(JSON.parse(new TextDecoder().decode(await crypto.key.generate({
      id: 'magic-key',
      type: 'application/jwk+json',
      algorithm: 'ES256'
    })))))
    expect(key.get(jose.web_key.kid)).toBe('magic-key')
    expect(key.get(jose.web_key.alg)).toBe('ES256')
  })
  it('parse', async () => {
    const jwk = crypto.key.parse<'ES256', 'application/jwk+json'>({
      key: await crypto.key.generate({
        id: 'magic-key',
        type: 'application/jwk+json',
        algorithm: 'ES256'
      }),
      type: 'application/jwk+json',
    })
    const key = new Map(Object.entries(jwk))
    expect(key.get(jose.web_key.kid)).toBe('magic-key')
    expect(key.get(jose.web_key.alg)).toBe('ES256')
  })

  it('parse polymorphic', async () => {
    const jwk = crypto.key.parse<'EdDSA', 'application/jwk+json'>({
      key: await crypto.key.generate({
        id: 'magic-key',
        type: 'application/jwk+json',
        algorithm: 'EdDSA'
      }),
      type: 'application/jwk+json',
    })
    const { crv } = jwk
    expect(crv).toBe('Ed25519')
    // crv is cannot narrow beyond Ed25519 | Ed448
  })

  it('parse fully specified', async () => {
    const jwk = crypto.key.parse<'Ed25519', 'application/jwk+json'>({
      key: await crypto.key.generate({
        id: 'magic-key',
        type: 'application/jwk+json',
        algorithm: 'Ed25519'
      }),
      type: 'application/jwk+json',
    })
    const { crv } = jwk
    expect(crv).toBe('Ed25519')
    // crv is narrowed to Ed25519
  })
})

describe('cose key', () => {
  it('generate', async () => {
    const bytes = await crypto.key.generate({
      id: 'magic-key',
      type: 'application/cose-key',
      algorithm: 'ES256'
    })
    const key = cbor.decode(bytes)
    expect(key.get(cose.cose_key.kid)).toBe('magic-key')
    expect(key.get(cose.cose_key.alg)).toBe(cose.algorithm.es256)
  })

  it('parse polymorphic EC2', async () => {
    const key = crypto.key.parse<'ES256', 'application/cose-key'>({
      key: await crypto.key.generate({
        type: 'application/cose-key',
        algorithm: 'ES256'
      }),
      type: 'application/cose-key',
    })
    const crv = key.get(cose.ec2.crv);
    expect(crv).toBe(cose.ec2_curves.p_256)
    // crv type can only narrow to 1, 2, 3
  })

  it('parse fully specified EC2', async () => {
    const key = crypto.key.parse<'ESP256', 'application/cose-key'>({
      key: await crypto.key.generate({
        type: 'application/cose-key',
        algorithm: 'ES256'
      }),
      type: 'application/cose-key',
    })
    const crv = key.get(cose.ec2.crv);
    expect(crv).toBe(cose.ec2_curves.p_256)
    // crv type is narrowed to 1
  })
})


