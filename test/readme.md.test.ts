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

const message0 = cose.cbor.encode(0)
const message1 = cose.cbor.encode('1')
const message2 = cose.cbor.encode([2, 2])
const message3 = cose.cbor.encode({ 3: 3 })
const entries = [message0, message1, message2, message3]
const leaves = entries.map(cose.merkle.leaf)

const message4 = cose.cbor.encode(['🔥', 4])
const message5 = cose.cbor.encode({ five: '💀' })
entries.push(message4)
entries.push(message5)
const leaves2 = entries.map(cose.merkle.leaf)

it('message sanity', async () => {
  expect(cose.cbor.decode(message0)).toEqual(0)
  expect(cose.cbor.decode(message1)).toEqual('1')
  expect(cose.cbor.decode(message2)).toEqual([2, 2])
  expect(cose.cbor.decode(message3)).toEqual({ 3: 3 })
  expect(cose.cbor.decode(message4)).toEqual(['🔥', 4])
  expect(cose.cbor.decode(message5)).toEqual({ five: '💀' })
})

let signed_inclusion_proof: Uint8Array

it('inclusion proof', async () => {
  signed_inclusion_proof = await cose.merkle.inclusion_proof({
    log_id,
    leaf_index: 2,
    leaves,
    signer,
  })
  const verified_inclusion_proof = await cose.merkle.verify_inclusion_proof({
    leaf: cose.merkle.leaf(entries[2]),
    signed_inclusion_proof,
    verifier,
  })

  const attached = cose.attachPayload(
    signed_inclusion_proof,
    verified_inclusion_proof,
  )
  const verified_root = await verifier.verify(attached)
  expect(verified_root).toEqual(verified_inclusion_proof)
  const diag = await cose.diagnostic(signed_inclusion_proof, {
    decode_payload: false,
    detached_payload: true,
  })
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
      # "inclusion-proof" : "h'3133312c342c322c3133302c3231362c36342c38382c33322c3136332c3135302c38352c3231322c3139342c3134312c32312c3135312c32342c3139312c3139352c34312c3132372c3134372c3231352c3135362c3130342c3133382c32382c32332c302c3139372c38302c38302c3131332c3134372c3133312c3131302c3231302c3135342c3135302c3133382c3231362c36342c38382c33322c38372c32342c3132352c3235352c31312c34352c322c3133312c3132372c3137332c3139362c3133312c3132322c3231352c3138362c3235332c3130332c372c35362c3138352c3133362c3132352c3130372c3134372c3232322c3234362c3234352c39342c33312c37322c3132332c313737'"    
      100 : h'3133312c342c322c3133302c3231362c36342c38382c33322c3136332c3135302c38352c3231322c3139342c3134312c32312c3135312c32342c3139312c3139352c34312c3132372c3134372c3231352c3135362c3130342c3133382c32382c32332c302c3139372c38302c38302c3131332c3134372c3133312c3131302c3231302c3135342c3135302c3133382c3231362c36342c38382c33322c38372c32342c3132352c3235352c31312c34352c322c3133312c3132372c3137332c3139362c3133312c3132322c3231352c3138362c3235332c3130332c372c35362c3138352c3133362c3132352c3130372c3134372c3232322c3234362c3234352c39342c33312c37322c3132332c313737' 
  },

  # Detached Payload

  # Signature
  h'df233b47cd787a5402cc82c7306d32a4768234ea90b86ff8a29af650f4f8f43199b05789ae190b0c8ceef31cde389332b8a5883f947937e2974fcba8bad44204'
])`)
})

it('consistency proof', async () => {
  const old_root = await cose.merkle.root({ leaves })
  const new_root = await cose.merkle.root({ leaves: leaves2 })
  const signed_consistency_proof = await cose.merkle.consistency_proof({
    log_id,
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
      # "consistency-proof" : "h'3133312c342c362c3133302c3231362c36342c38382c33322c31312c3231382c3137342c3231312c3138322c34382c32342c38382c3137362c3137322c3138392c3136312c3232342c3139352c3137302c38352c3234322c3232322c332c3132342c3233372c36382c33372c35382c3233302c3132312c3132332c39302c35302c38362c3133372c3130302c3231362c36342c38382c33322c3131372c3234312c3131392c3235332c352c3230372c34302c3231352c3136322c3134302c3130392c3232362c3234302c33362c37362c3137392c35392c3137332c3231352c37392c3235302c3233342c3232352c3131352c332c35392c3135372c3230362c34362c3131352c3136382c313731'"    
      200 : h'3133312c342c362c3133302c3231362c36342c38382c33322c31312c3231382c3137342c3231312c3138322c34382c32342c38382c3137362c3137322c3138392c3136312c3232342c3139352c3137302c38352c3234322c3232322c332c3132342c3233372c36382c33372c35382c3233302c3132312c3132332c39302c35302c38362c3133372c3130302c3231362c36342c38382c33322c3131372c3234312c3131392c3235332c352c3230372c34302c3231352c3136322c3134302c3130392c3232362c3234302c33362c37362c3137392c35392c3137332c3231352c37392c3235302c3233342c3232352c3131352c332c35392c3135372c3230362c34362c3131352c3136382c313731' 
  },

  # Protected Payload
  h'430b6fd7a7784c9f87cd6e78727a473acda6b66f6f85651f7a6a4cedf74c7fc4',

  # Signature
  h'5f5e0d53c624f90e6d4c19bbea79d837ea66f9c46fd21a592b567cd04365fdd0564e502d52d9cdb96ee3f52fc403c99a3d9d1b127591313af127713f82648543'
])`)
})
