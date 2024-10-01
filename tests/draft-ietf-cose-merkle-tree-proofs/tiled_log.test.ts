import fs from 'fs'
import * as cose from '../../src';

import { log } from './test_log';

it("cose receipts from a tiled transparency log", async () => {
  const encoder = new TextEncoder()
  for (let i = 0; i < 26; i++) {
    const record = encoder.encode(`entry-${i}`)
    log.write_record(record)
  }
  // prove 17 was in log at tree size 20
  const inclusion_proof = log.inclusion_proof(20, 17)
  const root_from_inclusion_proof = log.root_from_inclusion_proof(inclusion_proof, log.record_hash(encoder.encode(`entry-${17}`)))
  // prove log is append only from root at 20 to current log size
  const consistency_proof = log.consistency_proof(20, log.size())
  const root_from_consistency_proof = log.root_from_consistency_proof(root_from_inclusion_proof, consistency_proof)
  const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })
  const publicKeyJwk = cose.public_from_private({
    key: privateKeyJwk,
    type: "application/jwk+json"
  })
  const encoded_inclusion_proof = cose.encode_inclusion_proof(inclusion_proof)
  const inclusion_receipt = await cose.detached
    .signer({
      remote: cose.crypto.signer({
        privateKeyJwk
      })
    })
    .sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.alg, cose.algorithm.es256],
        [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256]
      ]),
      unprotectedHeader: cose.UnprotectedHeader([
        [cose.draft_headers.verifiable_data_proofs, cose.VerifiableDataStructureProofs([
          [cose.rfc9162_sha256_proof_types.inclusion, [encoded_inclusion_proof]],
        ])]
      ]),
      payload: root_from_inclusion_proof
    })
  fs.writeFileSync('./tests/draft-ietf-cose-merkle-tree-proofs/inclusion.receipt.diag', await cose.cbor.diag(inclusion_receipt, "application/cose"))
  const [inclusion_proof_from_unprotected_header] = cose.decode_inclusion_proof(inclusion_receipt)
  const reconstructed_inclusion_root_from_unprotected_header = log.root_from_inclusion_proof(inclusion_proof_from_unprotected_header, log.record_hash(encoder.encode(`entry-${17}`)))
  const verified_inclusion_receipt = await cose.detached
    .verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })
    .verify({
      coseSign1: inclusion_receipt,
      payload: reconstructed_inclusion_root_from_unprotected_header
    })
  // verified signed root from inclusion proof 
  expect(Buffer.from(verified_inclusion_receipt).toString('hex')).toBe(Buffer.from(root_from_inclusion_proof).toString('hex'))
  const encoded_consistency_proof = cose.encode_inclusion_proof(consistency_proof)
  const consistency_receipt = await cose.detached
    .signer({
      remote: cose.crypto.signer({
        privateKeyJwk
      })
    })
    .sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.alg, cose.algorithm.es256],
        [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256]
      ]),
      unprotectedHeader: cose.UnprotectedHeader([
        [cose.draft_headers.verifiable_data_proofs, cose.VerifiableDataStructureProofs([
          [cose.rfc9162_sha256_proof_types.consistency, [encoded_consistency_proof]],
        ])]
      ]),
      payload: root_from_consistency_proof
    })
  fs.writeFileSync('./tests/draft-ietf-cose-merkle-tree-proofs/consistency.receipt.diag', await cose.cbor.diag(consistency_receipt, "application/cose"))
  const [consistency_proof_from_unprotected_header] = cose.decode_consistency_proof(consistency_receipt)
  const reconstructed_consistency_root_from_unprotected_header = log.root_from_consistency_proof(verified_inclusion_receipt, consistency_proof_from_unprotected_header)
  const verified_consistency_receipt = await cose.detached
    .verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })
    .verify({
      coseSign1: consistency_receipt,
      payload: reconstructed_consistency_root_from_unprotected_header
    })

  // verified signed root from consistency proof 
  expect(Buffer.from(verified_consistency_receipt).toString('hex')).toBe(Buffer.from(root_from_consistency_proof).toString('hex'))

})