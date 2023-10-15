import cose, { CoseSigner, CoseVerifier } from '../src'

const log_id = `https://ts.example`
let signer: CoseSigner
let verifier: CoseVerifier

beforeAll(async () => {
  signer = await cose.signer({
    privateKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      d: 'o_95vWSheg19YU7viU3PmW_kRIWk14HiVLXDXiZjEL0',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
  verifier = await cose.verifier({
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      x: 'LYdh0ITBGLOUpywy0adFxXyaIaQapIEOLgfw7933TRE',
      y: 'I6R3hgQZf2topOWa0VBjEugRgHISJ39LvOlfVX29P0w',
    },
  })
})

const message0 = cose.cbor.web.encode(0)
const message1 = cose.cbor.web.encode('1')
const message2 = cose.cbor.web.encode([2, 2])
const message3 = cose.cbor.web.encode({ 3: 3 })
const entries = [message0, message1, message2, message3]
const leaves = entries.map(cose.merkle.leaf)

const message4 = cose.cbor.web.encode(['🔥', 4])
const message5 = cose.cbor.web.encode({ five: '💀' })
entries.push(message4)
entries.push(message5)
const leaves2 = entries.map(cose.merkle.leaf)

it('message sanity', async () => {
  expect(cose.cbor.web.decode(message0)).toEqual(0)
  expect(cose.cbor.web.decode(message1)).toEqual('1')
  expect(cose.cbor.web.decode(message2)).toEqual([2, 2])
  expect(cose.cbor.web.decode(message3)).toEqual({ 3: 3 })
  expect(cose.cbor.web.decode(message4)).toEqual(['🔥', 4])
  expect(cose.cbor.web.decode(message5)).toEqual({ five: '💀' })
})

let signed_inclusion_proof: Uint8Array

it('inclusion proof', async () => {
  signed_inclusion_proof = await cose.merkle.inclusion_proof({
    alg: signer.alg,
    kid: 'https://ts.example/urn:ietf:params:trans:inclusion:rfc9162_sha256:2:e7f16481e965db422b1d7dadf5c7f205ad6600445f5f9404a76cc85caab81688',
    leaf_index: 2,
    leaves,
    signer,
  })
  const verified_inclusion_proof = await cose.merkle.verify_inclusion_proof({
    leaf: cose.merkle.leaf(entries[2]),
    signed_inclusion_proof,
    verifier,
  })

  const attached = await cose.attachPayload(
    {
      signature: signed_inclusion_proof,
      payload: verified_inclusion_proof,
    }
  )
  const verified_root = await verifier.verify(attached)
  expect(verified_root).toEqual(verified_inclusion_proof)
  const diag = await cose.diagnostic(signed_inclusion_proof, {
    decode_payload: false,
    detached_payload: true,
  })
  // TODO: fix me to align with https://github.com/transmute-industries/cose/issues/5
  expect(diag).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a2012604588468747470733a2f2f74732e6578616d706c652f75726e3a696574663a706172616d733a7472616e733a696e636c7573696f6e3a726663393136325f7368613235363a323a65376631363438316539363564623432326231643764616466356337663230356164363630303434356635663934303461373663633835636161623831363838', 
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "kid" : h'68747470733a2f2f74732e6578616d706c652f75726e3a696574663a706172616d733a7472616e733a696e636c7573696f6e3a726663393136325f7368613235363a323a65376631363438316539363564623432326231643764616466356337663230356164363630303434356635663934303461373663633835636161623831363838',
  #   4 : https://ts.example/urn:ietf:params:trans:inclusion:rfc9162_sha256:2:e7f16481e965db422b1d7dadf5c7f205ad6600445f5f9404a76cc85caab81688
  # }

  # Unprotected Header
  {
      # "inclusion-proof" : "h'efbfbd0402efbfbd5820efbfbdefbfbd55efbfbdc28d15efbfbd18efbfbdefbfbd297fefbfbdd79c68efbfbd1c1700efbfbd505071efbfbdefbfbd6ed29aefbfbdefbfbd582057187defbfbd0b2d02efbfbd7fefbfbdc4837ad7baefbfbd670738efbfbdefbfbd7d6befbfbdefbfbdefbfbdefbfbd5e1f487befbfbd'"    
      100 : h'efbfbd0402efbfbd5820efbfbdefbfbd55efbfbdc28d15efbfbd18efbfbdefbfbd297fefbfbdd79c68efbfbd1c1700efbfbd505071efbfbdefbfbd6ed29aefbfbdefbfbd582057187defbfbd0b2d02efbfbd7fefbfbdc4837ad7baefbfbd670738efbfbdefbfbd7d6befbfbdefbfbdefbfbdefbfbd5e1f487befbfbd' 
  },

  # Detached Payload

  # Signature
  h'8acd89407e837d9c5853bbac11423ddb661e59c9f449b62c98e0282fbb3b0d832a368f0148c1ac687090e96bb47c963c3f41c49b92840276b0415e1217ac5618'
])`)
})

it('consistency proof', async () => {
  const old_root = await cose.merkle.root({
    alg: signer.alg,
    kid: log_id, leaves
  })
  const new_root = await cose.merkle.root({
    alg: signer.alg,
    kid: log_id, leaves: leaves2
  })
  const signed_consistency_proof = await cose.merkle.consistency_proof({
    alg: signer.alg,
    kid: 'https://ts.example/urn:ietf:params:trans:consistency:rfc9162_sha256:2:e7f16481e965db422b1d7dadf5c7f205ad6600445f5f9404a76cc85caab81688',
    signed_inclusion_proof,
    leaves: leaves2,
    signer,
  })
  const verified = await cose.merkle.verify_consistency_proof({
    old_root,
    signed_consistency_proof,
    verifier,
  })
  expect(verified).toBe(true)
  const verified_root = await verifier.verify(signed_consistency_proof)
  expect(verified_root).toEqual(new_root)
  const diag = await cose.diagnostic(signed_consistency_proof, {
    decode_payload: false,
    detached_payload: false,
  })
  // TODO: fix me to align with https://github.com/transmute-industries/cose/issues/5
  expect(diag).toBe(`# COSE_Sign1
18([

  # Protected Header
  h'a2012604588668747470733a2f2f74732e6578616d706c652f75726e3a696574663a706172616d733a7472616e733a636f6e73697374656e63793a726663393136325f7368613235363a323a65376631363438316539363564623432326231643764616466356337663230356164363630303434356635663934303461373663633835636161623831363838', 
  # {
  #   "alg" : "ES256",
  #   1 : -7,
  #   "kid" : h'68747470733a2f2f74732e6578616d706c652f75726e3a696574663a706172616d733a7472616e733a636f6e73697374656e63793a726663393136325f7368613235363a323a65376631363438316539363564623432326231643764616466356337663230356164363630303434356635663934303461373663633835636161623831363838',
  #   4 : https://ts.example/urn:ietf:params:trans:consistency:rfc9162_sha256:2:e7f16481e965db422b1d7dadf5c7f205ad6600445f5f9404a76cc85caab81688
  # }

  # Unprotected Header
  {
      # "consistency-proof" : "h'efbfbd0406efbfbd58200bdaaed3b6301858efbfbdefbfbdefbfbdefbfbdefbfbdc3aa55efbfbdefbfbd037cefbfbd44253aefbfbd797b5a3256efbfbd64582075efbfbd77efbfbd05efbfbd28d7a2efbfbd6defbfbdefbfbd244cefbfbd3befbfbdefbfbd4fefbfbdefbfbdefbfbd73033befbfbdefbfbd2e73efbfbdefbfbd'"    
      200 : h'efbfbd0406efbfbd58200bdaaed3b6301858efbfbdefbfbdefbfbdefbfbdefbfbdc3aa55efbfbdefbfbd037cefbfbd44253aefbfbd797b5a3256efbfbd64582075efbfbd77efbfbd05efbfbd28d7a2efbfbd6defbfbdefbfbd244cefbfbd3befbfbdefbfbd4fefbfbdefbfbdefbfbd73033befbfbdefbfbd2e73efbfbdefbfbd' 
  },

  # Protected Payload
  h'430b6fd7a7784c9f87cd6e78727a473acda6b66f6f85651f7a6a4cedf74c7fc4',

  # Signature
  h'6710c3528cc65b2ca8e9fa5ff31b8a9d2a90f81b8466d25f653b2f657cd288ac4452d9104fab6556bb423c993e672f040c4cc4b1e3ff69a76f36c6aaa023aa71'
])`)
})
