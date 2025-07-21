# COSE Receipts with CCF Profile

This directory contains the implementation of the [COSE Receipts with CCF Profile](https://www.ietf.org/archive/id/draft-birkholz-cose-receipts-ccf-profile-04.txt) draft.

## Overview

The CCF (Confidential Consortium Framework) profile defines a new verifiable data structure type for COSE Signed Merkle Tree Proofs specifically designed for transaction ledgers produced via Trusted Execution Environments (TEEs). This implementation provides stronger tamper-evidence guarantees compared to standard Merkle tree implementations.

## Key Features

- **CCF Leaf Structure**: Implements the specific leaf format with internal transaction hash, evidence, and data hash
- **CCF Inclusion Proofs**: Supports the CCF-specific inclusion proof format with left/right path elements
- **Merkle Root Computation**: Implements the CCF-specific root computation algorithm
- **CBOR Encoding/Decoding**: Full support for CCF data structures in CBOR format
- **Receipt Creation and Verification**: Complete workflow for creating and verifying CCF inclusion receipts

## Data Structures

### CCF Leaf

```typescript
interface CCFLeaf {
  internal_transaction_hash: Uint8Array  // 32-byte hash
  internal_evidence: string              // 1-1024 byte string
  data_hash: Uint8Array                  // 32-byte hash
}
```

### CCF Proof Element

```typescript
interface CCFProofElement {
  left: boolean                          // Position indicator
  hash: Uint8Array                       // 32-byte hash
}
```

### CCF Inclusion Proof

```typescript
interface CCFInclusionProof {
  leaf: CCFLeaf
  path: CCFProofElement[]
}
```

## Usage

### Basic Usage

```typescript
import * as cose from '@transmute/cose'
import crypto from 'crypto'

// Create a CCF leaf
const leaf: cose.CCFLeaf = {
  internal_transaction_hash: new Uint8Array(32).fill(1),
  internal_evidence: 'ccf-commit-evidence-12345',
  data_hash: new Uint8Array(32).fill(2)
}

// Validate the leaf
if (!cose.validateCCFLeaf(leaf)) {
  throw new Error('Invalid CCF leaf')
}

// Create hash function
const hashFunction = (data: Uint8Array) => {
  return new Uint8Array(crypto.createHash('sha256').update(data).digest())
}

// Create CCF inclusion proof
const proof: cose.CCFInclusionProof = {
  leaf: leaf,
  path: [
    { left: true, hash: new Uint8Array(32).fill(3) }
  ]
}

// Compute Merkle root
const root = cose.computeCCFRoot(proof, hashFunction)

// Extract index from proof
const index = cose.extractIndexFromCCFProof(proof)
```

### Creating and Verifying Receipts

```typescript
// Create cryptographic keys
const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
  type: 'application/jwk+json',
  algorithm: 'ES256',
})
const publicKeyJwk = cose.public_from_private({
  key: privateKeyJwk,
  type: 'application/jwk+json',
})

// Create signer and verifier
const signer = cose.detached.signer({
  remote: cose.crypto.signer({ privateKeyJwk }),
})
const verifier = cose.detached.verifier({
  resolver: { resolve: async () => publicKeyJwk },
})

// Create CCF inclusion receipt
const receipt = await cose.createCCFInclusionReceipt(
  proof,
  signer,
  hashFunction,
  publicKeyJwk
)

// Verify the receipt
const isValid = await cose.verifyCCFInclusionReceipt(
  receipt,
  hashFunction,
  verifier
)
```

### CBOR Encoding/Decoding

```typescript
// Encode CCF leaf
const encodedLeaf = cose.encodeCCFLeaf(leaf)
const decodedLeaf = cose.decodeCCFLeaf(encodedLeaf)

// Encode CCF inclusion proof
const encodedProof = cose.encodeCCFInclusionProof(proof)
const decodedProof = cose.decodeCCFInclusionProof(encodedProof)
```

## Constants

```typescript
// Verifiable data structure types
cose.ccf_verifiable_data_structures.ccf_ledger_sha256 // 2

// Proof types
cose.ccf_proof_types.inclusion // -1

// Transparency map
cose.ccf_transparency // Map with CCF-specific values
```

## Algorithm Details

### Leaf Hash Computation

The CCF leaf hash is computed as:
```
h := proof.leaf.internal-transaction-hash || HASH(proof.leaf.internal-evidence) || proof.leaf.data-hash
```

### Root Computation

The Merkle root is computed using the algorithm:
```
compute_root(proof):
  h := proof.leaf.internal-transaction-hash || HASH(proof.leaf.internal-evidence) || proof.leaf.data-hash
  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h
```

### Index Extraction

The index is extracted from the proof path by treating the left/right bits as a binary number:
- `left: true` = bit 0
- `left: false` = bit 1

## Testing

Run the tests with:

```bash
npm test -- --testPathPattern=ccf-profile
```

## Example

See `examples/ccf-profile-example.ts` for a complete working example.

## References

- [COSE Receipts with CCF Profile Draft](https://www.ietf.org/archive/id/draft-birkholz-cose-receipts-ccf-profile-04.txt)
- [Confidential Consortium Framework](https://github.com/microsoft/ccf)
- [COSE Receipts Draft](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/) 