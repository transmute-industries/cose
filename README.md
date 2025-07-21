# cose

[![CI](https://github.com/transmute-industries/cose/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/cose/actions/workflows/ci.yml)

## Usage

🔥 This package is not stable or suitable for production use 🚧

```bash
npm install '@transmute/cose'
```

```js
const cose = require("@transmute/cose");
```

```ts
import * as cose from "@transmute/cose";
```

## Examples

### COSE Receipts & Signature Transparency

```ts
import crypto from "crypto";
import sqlite from "better-sqlite3";
import * as cose from "@transmute/cose";

const create_software_producer = async ({
  website,
  product,
}: {
  website: string;
  product: string;
}) => {
  const privateKeyJwk = await cose.crypto.key.generate<
    "ES256",
    "application/jwk+json"
  >({
    type: "application/jwk+json",
    algorithm: "ES256",
  });
  const publicKeyJwk = cose.public_from_private({
    key: privateKeyJwk,
    type: "application/jwk+json",
  });
  const signer = cose.hash.signer({
    remote: cose.crypto.signer({
      privateKeyJwk,
    }),
  });
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk;
      },
    },
  });

  return { website, product, signer, verifier, public_key: publicKeyJwk };
};

const create_sqlite_log = (database: string) => {
  const db = new sqlite(database);

  db.prepare(
    `
  CREATE TABLE IF NOT EXISTS tiles 
  (id TEXT PRIMARY KEY, data BLOB);
  
  `
  ).run();

  db.prepare(
    `
  CREATE TABLE IF NOT EXISTS kv 
  (key text unique, value text);
  `
  ).run();

  const hash_size = 32;
  const tile_height = 2;

  const log = new cose.TileLog({
    tile_height,
    hash_size,
    read_tree_size: () => {
      const rows = db
        .prepare(
          `
        SELECT * FROM kv
        WHERE key = 'tree_size'
                `
        )
        .all();
      const [row] = rows as { key: string; value: string }[];
      try {
        return parseInt(row.value, 10);
      } catch (e) {
        // console.error(e)
        return 0;
      }
    },
    update_tree_size: (new_tree_size: number) => {
      try {
        db.prepare(
          `
      INSERT OR REPLACE INTO kv (key, value)
      VALUES( 'tree_size',	'${new_tree_size}');
              `
        ).run();
      } catch (e) {
        // console.error(e)
        // ignore errors
      }
    },

    read_tree_root: function () {
      const rows = db
        .prepare(
          `
        SELECT * FROM kv
        WHERE key = 'tree_root'
                `
        )
        .all();
      const [row] = rows as { key: string; value: string }[];
      try {
        return new Uint8Array(Buffer.from(row.value, "hex"));
      } catch (e) {
        return null;
      }
    },
    update_tree_root: (new_tree_root: Uint8Array): void => {
      try {
        db.prepare(
          `
      INSERT OR REPLACE INTO kv (key, value)
      VALUES( 'tree_root',	'${Buffer.from(new_tree_root).toString("hex")}');
              `
        ).run();
      } catch (e) {
        // ignore errors
      }
    },

    read_tile: (tile: string): Uint8Array => {
      const [base_tile] = tile.split(".");
      // look for completed tiles first
      for (let i = 4; i > 0; i--) {
        const tile_path = base_tile + "." + i;
        const rows = db
          .prepare(
            `
            SELECT * FROM tiles
            WHERE id = '${tile_path}'
                    `
          )
          .all();
        if (rows.length) {
          const [row] = rows as { id: string; data: Uint8Array }[];
          return row.data;
        }
      }
      return new Uint8Array(32);
    },
    update_tiles: function (
      tile_path: string,
      start: number,
      end: number,
      stored_hash: Uint8Array
    ) {
      if (end - start !== 32) {
        // this hash was an intermediate of the tile
        // so it will never be persisted
        return null;
      }
      let tile_data = this.read_tile(tile_path);
      if (tile_data.length < end) {
        const expanded_tile_data = new Uint8Array(tile_data.length + 32);
        expanded_tile_data.set(tile_data);
        tile_data = expanded_tile_data;
      }
      tile_data.set(stored_hash, start);
      try {
        db.prepare(
          `
      INSERT INTO tiles (id, data)
      VALUES( '${tile_path}',	x'${Buffer.from(tile_data).toString("hex")}');
              `
        ).run();
      } catch (e) {
        // ignore errors
      }
      return tile_data;
    },
    hash_function: (data: Uint8Array) => {
      return new Uint8Array(crypto.createHash("sha256").update(data).digest());
    },
  });

  return { db, log };
};

const create_transparency_service = async ({
  website,
  database,
}: {
  website: string;
  database: string;
}) => {
  const privateKeyJwk = await cose.crypto.key.generate<
    "ES256",
    "application/jwk+json"
  >({
    type: "application/jwk+json",
    algorithm: "ES256",
  });
  const publicKeyJwk = cose.public_from_private({
    key: privateKeyJwk,
    type: "application/jwk+json",
  });
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk,
    }),
  });
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return publicKeyJwk;
      },
    },
  });
  const { log, db } = create_sqlite_log(database);
  const register_signed_statement = async (signed_statement: Uint8Array) => {
    // registration policy goes here...
    // for this test, we accept everything
    const record = await cose.prepare_for_inclusion(signed_statement);
    log.write_record(record);
    const root = log.root();
    const index = log.size();
    const decoded = cose.cbor.decode(signed_statement);
    const signed_statement_header = cose.cbor.decode(decoded.value[0]);
    const signed_statement_claims = signed_statement_header.get(
      cose.header.cwt_claims
    );
    const inclusion_proof = log.inclusion_proof(index, index - 1);
    return signer.sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.header.kid, publicKeyJwk.kid],
        [cose.header.alg, cose.algorithm.es256],
        [
          cose.draft_headers.verifiable_data_structure,
          cose.verifiable_data_structures.rfc9162_sha256,
        ],
        [
          cose.header.cwt_claims,
          cose.CWTClaims([
            [cose.cwt_claims.iss, website], // issuer notary
            // receipt subject is statement subject.
            // ... could be receipts have different subject id
            [
              cose.cwt_claims.sub,
              signed_statement_claims.get(cose.cwt_claims.sub),
            ],
          ]),
        ],
      ]),
      unprotectedHeader: cose.UnprotectedHeader([
        [
          cose.draft_headers.verifiable_data_proofs,
          cose.VerifiableDataStructureProofs([
            [cose.rfc9162_sha256_proof_types.inclusion, [inclusion_proof]],
          ]),
        ],
      ]),
      payload: root,
    });
  };
  return {
    website,
    db,
    signer,
    verifier,
    log,
    register_signed_statement,
    public_key: publicKeyJwk,
  };
};

const software_producer = await create_software_producer({
  website: "https://green.example",
  product: "https://green.example/cli@v1.2.3",
});

const blue_notary = await create_transparency_service({
  website: "https://blue.example",
  database: "./tests/draft-ietf-scitt-architecture/blue.transparency.db",
});

const orange_notary = await create_transparency_service({
  website: "https://orange.example",
  database: "./tests/draft-ietf-scitt-architecture/orange.transparency.db",
});

const statement = Buffer.from("large file that never moves over a network");

const signed_statement = await software_producer.signer.sign({
  protectedHeader: cose.ProtectedHeader([
    [cose.header.kid, software_producer.public_key.kid],
    [cose.header.alg, cose.algorithm.es256],
    [cose.draft_headers.payload_hash_algorithm, cose.algorithm.sha_256],
    [cose.draft_headers.payload_preimage_content_type, "application/spdx+json"],
    [cose.draft_headers.payload_location, "https://cloud.example/sbom/42"],
    [
      cose.header.cwt_claims,
      cose.CWTClaims([
        [cose.cwt_claims.iss, software_producer.website],
        [cose.cwt_claims.sub, software_producer.product],
      ]),
    ],
  ]),
  payload: statement,
});

const blue_receipt = await blue_notary.register_signed_statement(
  signed_statement
);
const transparent_statement = await cose.add_receipt(
  signed_statement,
  blue_receipt
);
const orange_receipt = await orange_notary.register_signed_statement(
  transparent_statement
);
const signed_statement_with_multiple_receipts = await cose.add_receipt(
  transparent_statement,
  orange_receipt
);
const statement_hash = new Uint8Array(
  await (await cose.crypto.subtle()).digest("SHA-256", statement)
);
const verification = await verify_transparent_statement(
  statement_hash,
  signed_statement_with_multiple_receipts,
  {
    tree_hasher: blue_notary.log.tree_hasher, // both logs use same tree algorithm
    resolver: {
      resolve: async (token: Buffer) => {
        const decoded = cose.cbor.decode(token);
        const header = cose.cbor.decode(decoded.value[0]);
        const kid = header.get(cose.header.kid);
        switch (kid) {
          case software_producer.public_key.kid: {
            return software_producer.public_key;
          }
          case blue_notary.public_key.kid: {
            return blue_notary.public_key;
          }
          case orange_notary.public_key.kid: {
            return orange_notary.public_key;
          }
          default: {
            throw new Error("Unknown key: " + kid);
          }
        }
      },
    },
  }
);
```

### COSE Receipts with CCF Profile

The library also supports the [COSE Receipts with CCF Profile](https://www.ietf.org/archive/id/draft-birkholz-cose-receipts-ccf-profile-04.txt) draft, which provides stronger tamper-evidence guarantees for transaction ledgers produced via Trusted Execution Environments (TEEs).

```ts
import crypto from 'crypto'
import * as cose from '@transmute/cose'

// Create a CCF leaf structure
const ccfLeaf: cose.CCFLeaf = {
  internal_transaction_hash: new Uint8Array(32).fill(1),
  internal_evidence: 'ccf-commit-evidence-12345',
  data_hash: new Uint8Array(32).fill(2)
}

// Validate the leaf
if (!cose.validateCCFLeaf(ccfLeaf)) {
  throw new Error('Invalid CCF leaf')
}

// Create hash function
const hashFunction = (data: Uint8Array) => {
  return new Uint8Array(crypto.createHash('sha256').update(data).digest())
}

// Create CCF inclusion proof
const ccfProof: cose.CCFInclusionProof = {
  leaf: ccfLeaf,
  path: [
    { left: true, hash: new Uint8Array(32).fill(3) }
  ]
}

// Compute Merkle root
const root = cose.computeCCFRoot(ccfProof, hashFunction)

// Extract index from proof
const index = cose.extractIndexFromCCFProof(ccfProof)

// CBOR encoding/decoding
const encodedLeaf = cose.encodeCCFLeaf(ccfLeaf)
const decodedLeaf = cose.decodeCCFLeaf(encodedLeaf)

const encodedProof = cose.encodeCCFInclusionProof(ccfProof)
const decodedProof = cose.decodeCCFInclusionProof(encodedProof)
```

See `examples/ccf-profile-example.ts` for a complete working example.

Example of a transparent signed statement with multiple receipts in extended diagnostic notation:

#### Transparent Statement

```edn
/ cose-sign1 / 18([
  / protected   / <<{
    / key / 4 : "vCl7UcS0ZZY99VpRthDc-0iUjLdfLtnmFqLJ2-Tt8N4",
    / algorithm / 1 : -7,  # ES256
    / hash  / -6800 : -16, # SHA-256
    / content  / -6802 : "application/spdx+json",
    / location / -6801 : "https://cloud.example/sbom/42",
    / claims / 15 : {
      / issuer  / 1 : "https://green.example",
      / subject / 2 : "https://green.example/cli@v1.2.3",
    },
  }>>,
  / unprotected / {
    / receipts / 394 : {
      <</ cose-sign1 / 18([
        / protected   / <<{
          / key / 4 : "mxA4KiOkQFZ-dkLebSo3mLOEPR7rN8XtxkJe45xuyJk",
          / algorithm / 1 : -7,  # ES256
          / notary    / 395 : 1, # RFC9162 SHA-256
          / claims / 15 : {
            / issuer  / 1 : "https://blue.example",
            / subject / 2 : "https://green.example/cli@v1.2.3",
          },
        }>>,
        / unprotected / {
          / proofs / 396 : {
            / inclusion / -1 : [
              <<[
                / size / 9, / leaf / 8,
                / inclusion path /
                h'7558a95f...e02e35d6'
              ]>>
            ],
          },
        },
        / payload     / null,
        / signature   / h'02d227ed...ccd3774f'
      ])>>,
      <</ cose-sign1 / 18([
        / protected   / <<{
          / key / 4 : "ajOkeBTJou_wPrlExLMw7L9OTCD5ZIOBYc-O6LESe9c",
          / algorithm / 1 : -7,  # ES256
          / notary    / 395 : 1, # RFC9162 SHA-256
          / claims / 15 : {
            / issuer  / 1 : "https://orange.example",
            / subject / 2 : "https://green.example/cli@v1.2.3",
          },
        }>>,
        / unprotected / {
          / proofs / 396 : {
            / inclusion / -1 : [
              <<[
                / size / 6, / leaf / 5,
                / inclusion path /
                h'9352f974...4ffa7ce0',
                h'54806f32...f007ea06'
              ]>>
            ],
          },
        },
        / payload     / null,
        / signature   / h'36581f38...a5581960'
      ])>>
    },
  },
  / payload     / h'0167c57c...deeed6d4',
  / signature   / h'2544f2ed...5840893b'
])

```

### COSE RFCs

- [RFC9360 - Header Parameters for Carrying and Referencing X.509 Certificates](https://datatracker.ietf.org/doc/rfc9360/)
- [RFC9052 - Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC9053 - Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)

### COSE Drafts

- [COSE Receipts](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- [COSE Hash Envelope](https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/)
- [COSE HPKE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)

### SCITT Drafts

- [SCITT Architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```

<img src="./transmute-banner.png" />

#### [Questions? Contact Transmute](https://transmute.typeform.com/to/RshfIw?typeform-source=cose)
