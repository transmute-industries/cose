
import fs from 'fs'

import * as cose from '../../src';

import { create_software_producer, create_transparency_service } from './test_utils'

it('', async () => {

  const software_producer = await create_software_producer({
    website: 'https://green.software.vendor.example',
    product: 'https://green.software.vendor.example/awesome-cli@v1.2.3'
  })

  const blue_notary = await create_transparency_service({
    notary: 'https://blue.software.vendor.example',
    database: './tests/draft-ietf-scitt-architecture/blue.transparency.db'
  })

  const signed_statement = await software_producer.signer.sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.header.kid, software_producer.kid],
      [cose.header.alg, cose.algorithm.es256],
      [cose.draft_headers.payload_hash_algorithm, cose.algorithm.sha_256],
      [cose.draft_headers.payload_preimage_content_type, 'application/spdx+json'],
      [cose.draft_headers.payload_location, 'https://cloud.example/sbom/42'],
      [cose.header.cwt_claims, cose.CWTClaims([
        [1, software_producer.website], // iss
        [2, software_producer.product]  // sub
      ])]
    ]),
    payload: fs.readFileSync('./package.json')
  })

  const receipt = await blue_notary.register_signed_statement(signed_statement)


  // console.log(receipt)

})