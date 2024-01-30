import { CoMETRE } from '@transmute/rfc9162'

import { RequestSignedMerkleRoot } from '../types'

export const sign_root = async ({
  alg, kid,
  leaves,
  signer,
}: RequestSignedMerkleRoot) => {
  const root = CoMETRE.RFC9162_SHA256.root(leaves)
  if (!signer) {
    return root
  }
  const signed_root = await signer.sign({
    protectedHeader: { alg, kid },
    payload: root,
  })
  return signed_root
}
