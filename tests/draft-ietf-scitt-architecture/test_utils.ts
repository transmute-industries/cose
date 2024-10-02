
import * as cose from '../../src'

import { create_sqlite_log } from '../draft-ietf-cose-merkle-tree-proofs/test_log'

type create_transparency_params = {
  website: string
  database: string
}

export const create_software_producer = async ({ website, product }: { website: string, product: string }) => {
  const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })
  const publicKeyJwk = cose.public_from_private({
    key: privateKeyJwk,
    type: "application/jwk+json"
  })
  const signer = cose.hash.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })
  const verifier = cose.detached
    .verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })


  return { website, product, signer, verifier, kid: publicKeyJwk.kid }
}

export const create_transparency_service = async ({ website, database }: create_transparency_params) => {


  const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
    type: "application/jwk+json",
    algorithm: "ES256"
  })

  const publicKeyJwk = cose.public_from_private({
    key: privateKeyJwk,
    type: "application/jwk+json"
  })

  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk
    })
  })

  const verifier = cose.detached
    .verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })

  const { log, db } = create_sqlite_log(database)

  const register_signed_statement = async (signed_statement: Uint8Array) => {
    const root = log.root()
    const index = log.size()
    log.write_record(signed_statement)

    const decoded = cose.cbor.decode(signed_statement)
    const signed_statement_header = cose.cbor.decode(decoded.value[0])
    const signed_statement_claims = signed_statement_header.get(cose.header.cwt_claims)
    // console.log(signed_statement_header)
    const inclusion_proof = log.inclusion_proof(index + 1, index)
    return signer.sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.kid, publicKeyJwk.kid],
        [cose.header.alg, cose.algorithm.es256],
        [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256],
        [cose.header.cwt_claims, cose.CWTClaims([
          // TODO: IANA registry for CWT Claims with types.
          [1, website], // issuer notary
          // receipt subject is statement subject.
          // ... could be receipts have different subject id
          [2, signed_statement_claims.get(2)]
        ])]
      ]),
      unprotectedHeader: cose.UnprotectedHeader([
        [cose.draft_headers.verifiable_data_proofs, cose.VerifiableDataStructureProofs([
          [cose.rfc9162_sha256_proof_types.inclusion, [inclusion_proof]],
        ])]
      ]),
      payload: root
    })
  }

  return {
    website,
    db,
    signer,
    verifier,
    log,
    register_signed_statement
  }

}