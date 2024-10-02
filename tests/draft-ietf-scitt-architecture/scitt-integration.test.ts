
import fs from 'fs'

import * as cose from '../../src';
import { create_software_producer, create_transparency_service, verify_transparent_statement } from './test_utils'

it('integration test', async () => {

  const software_producer = await create_software_producer({
    website: 'https://green.example',
    product: 'https://green.example/cli@v1.2.3'
  })

  const blue_notary = await create_transparency_service({
    website: 'https://blue.example',
    database: './tests/draft-ietf-scitt-architecture/blue.transparency.db'
  })

  const orange_notary = await create_transparency_service({
    website: 'https://orange.example',
    database: './tests/draft-ietf-scitt-architecture/orange.transparency.db'
  })

  const statement = Buffer.from('large file that never moves over a network')

  const signed_statement = await software_producer.signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.kid, software_producer.public_key.kid],
      [cose.header.alg, cose.algorithm.es256],
      [cose.draft_headers.payload_hash_algorithm, cose.algorithm.sha_256],
      [cose.draft_headers.payload_preimage_content_type, 'application/spdx+json'],
      [cose.draft_headers.payload_location, 'https://cloud.example/sbom/42'],
      [cose.header.cwt_claims, cose.CWTClaims([
        [cose.cwt_claims.iss, software_producer.website],
        [cose.cwt_claims.sub, software_producer.product]
      ])]
    ]),
    payload: statement
  })

  const blue_receipt = await blue_notary.register_signed_statement(signed_statement)
  const transparent_statement = await cose.add_receipt(signed_statement, blue_receipt)
  const orange_receipt = await orange_notary.register_signed_statement(transparent_statement)
  const signed_statement_with_multiple_receipts = await cose.add_receipt(transparent_statement, orange_receipt)
  // fs.writeFileSync('./tests/draft-ietf-scitt-architecture/transparent_signed_statement.diag', await cose.cbor.diag(signed_statement_with_multiple_receipts, "application/cose"))

  const statement_hash = new Uint8Array(await (await cose.crypto.subtle()).digest("SHA-256", statement))
  const verification = await verify_transparent_statement(statement_hash, signed_statement_with_multiple_receipts, {
    tree_hasher: blue_notary.log.tree_hasher, // both logs use same tree algorithm
    resolver: {
      resolve: async (token: Buffer) => {
        const decoded = cose.cbor.decode(token)
        const header = cose.cbor.decode(decoded.value[0])
        const kid = header.get(cose.header.kid)
        switch (kid) {
          case software_producer.public_key.kid: {
            return software_producer.public_key
          }
          case blue_notary.public_key.kid: {
            return blue_notary.public_key
          }
          case orange_notary.public_key.kid: {
            return orange_notary.public_key
          }
          default: {
            throw new Error('Unknown key: ' + kid)
          }
        }
      }
    }
  })
  // fs.writeFileSync('./tests/draft-ietf-scitt-architecture/transparent_signed_statement.verification.json', JSON.stringify(verification, null, 2))
})