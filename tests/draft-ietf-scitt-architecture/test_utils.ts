import crypto from 'crypto'
import sqlite from 'better-sqlite3'
import * as cose from '../../src'
type create_transparency_params = {
  notary: string
  database: string
}

const hash_size = 32
const tile_height = 2

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

export const create_transparency_service = async ({ notary, database }: create_transparency_params) => {
  const db = new sqlite(database);
  db.prepare(`
    CREATE TABLE IF NOT EXISTS tiles 
    (id TEXT PRIMARY KEY, data BLOB);
            `).run()

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

  const log = new cose.TileLog({
    tile_height,
    hash_size,
    hash_function: (data: Uint8Array) => {
      return new Uint8Array(crypto.createHash('sha256').update(data).digest());
    },
    read_tile: (tile: string): Uint8Array => {
      const [base_tile] = tile.split('.')
      // look for completed tiles first
      for (let i = 4; i > 0; i--) {
        const tile_path = base_tile + '.' + i
        const rows = db.prepare(`
              SELECT * FROM tiles
              WHERE id = '${tile_path}'
                      `).all();
        if (rows.length) {
          const [row] = rows as { id: string, data: Uint8Array }[]
          return row.data
        }
      }
      return new Uint8Array(32)
    },
    update_tiles: function (tile_path: string, start: number, end: number, stored_hash: Uint8Array) {
      if (end - start !== 32) {
        // this hash was an intermediate of the tile
        // so it will never be persisted
        return null
      }
      let tile_data = this.read_tile(tile_path)
      if (tile_data.length < end) {
        const expanded_tile_data = new Uint8Array(tile_data.length + 32)
        expanded_tile_data.set(tile_data)
        tile_data = expanded_tile_data
      }
      tile_data.set(stored_hash, start)
      try {
        db.prepare(`
        INSERT INTO tiles (id, data)
        VALUES( '${tile_path}',	x'${Buffer.from(tile_data).toString('hex')}');
                `).run()
      } catch (e) {
        // ignore errors
      }
      return tile_data
    }
  })

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
          [1, notary], // issuer notary
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
    notary,
    db,
    signer,
    verifier,
    log,
    register_signed_statement
  }

}