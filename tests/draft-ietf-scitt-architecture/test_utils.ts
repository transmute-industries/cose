
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


  return { website, product, signer, verifier, public_key: publicKeyJwk }
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
    // registration policy goes here...
    // for this test, we accept everything

    const record = await cose.prepare_for_inclusion(signed_statement)
    log.write_record(record)

    const root = log.root()
    const index = log.size()
    const decoded = cose.cbor.decode(signed_statement)
    const signed_statement_header = cose.cbor.decode(decoded.value[0])
    const signed_statement_claims = signed_statement_header.get(cose.header.cwt_claims)
    const inclusion_proof = log.inclusion_proof(index, index - 1)
    return signer.sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.kid, publicKeyJwk.kid],
        [cose.header.alg, cose.algorithm.es256],
        [cose.draft_headers.verifiable_data_structure, cose.verifiable_data_structures.rfc9162_sha256],
        [cose.header.cwt_claims, cose.CWTClaims([

          [cose.cwt_claims.iss, website], // issuer notary
          // receipt subject is statement subject.
          // ... could be receipts have different subject id
          [cose.cwt_claims.sub, signed_statement_claims.get(cose.cwt_claims.sub)]
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
    register_signed_statement,
    public_key: publicKeyJwk
  }

}

export const verify_transparent_statement = async (statement_hash: Uint8Array, signature: Uint8Array, config: any) => {
  // first, we verify the signed statement
  const verifier = cose.detached.verifier(config)
  const verified_statement = await verifier.verify({
    coseSign1: signature,
    payload: statement_hash
  })
  const decoded_signed_statement = cose.cbor.decode(signature)
  const signed_statement_claims = cose.cbor.decode(decoded_signed_statement.value[0]).get(cose.header.cwt_claims)
  const result = {
    issuer: signed_statement_claims.get(cose.cwt_claims.iss),
    subject: signed_statement_claims.get(cose.cwt_claims.sub),
    verified_statement_hash: cose.to_hex(verified_statement),
    receipts: []
  } as Record<string, any>
  const decoded_signature = cose.cbor.decode(signature)
  const receipts = decoded_signature.value[1].get(cose.draft_headers.receipts)
  // next verify each receipt
  for (const receipt of receipts) {
    const decoded_receipt = cose.cbor.decode(receipt)
    const proofs = decoded_receipt.value[1].get(cose.draft_headers.verifiable_data_proofs)
    // first proof of inclusion only
    const [[size, index, inclusion_path]] = proofs.get(cose.rfc9162_sha256_proof_types.inclusion)
    // we need to remove receipts in order to compute leaf hash
    const record = await cose.prepare_for_inclusion(signature)
    const record_hash = config.tree_hasher.hash_leaf(record)
    const root = cose.root_from_record_proof(config.tree_hasher, inclusion_path, size, index, record_hash)
    const verified_root = await verifier.verify({
      coseSign1: receipt,
      payload: Buffer.from(root)
    })
    const receipt_claims = cose.cbor.decode(decoded_receipt.value[0]).get(cose.header.cwt_claims)
    result.receipts.push({
      issuer: receipt_claims.get(cose.cwt_claims.iss),
      subject: receipt_claims.get(cose.cwt_claims.sub),
      verified_root: cose.to_hex(verified_root)
    })
  }
  return result
}