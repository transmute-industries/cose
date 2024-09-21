import { algorithms_to_labels, labels_to_algorithms } from "../assignments/cose";


algorithms_to_labels.set('ESP256', -9)
labels_to_algorithms.set(-9, 'ESP256')

algorithms_to_labels.set('ESP384', -48)
labels_to_algorithms.set(-48, 'ESP384')

export const less_specified = {
  'ESP384': 'ES384',
  'ESP256': 'ES256',
  'ES256': 'ES256',
  'ES384': 'ES384',
  'ES512': 'ES512'
}

export enum draft_headers {
  // https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/
  payload_hash_algorithm = -6800,
  payload_location = -6801,
  payload_preimage_content_type = -6802,

  // https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/
  receipts = 394,
  verifiable_data_structure = 395,
  verifiable_data_proofs = 395


}

export { algorithms_to_labels, labels_to_algorithms }