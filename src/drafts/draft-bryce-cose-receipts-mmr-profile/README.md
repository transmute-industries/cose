# Draft COSE Receipts for MMRs

This directory contains the implementation for the draft specification [draft-bryce-cose-receipts-mmr-profile-00](https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-00.txt) on COSE Receipts for Merkle Mountain Ranges (MMRs).

## Overview

This specification defines a new verifiable data structure profile for COSE Receipts specifically for use with ledgers based on post-order traversal binary Merkle trees, also known as Merkle Mountain Ranges (MMRs). MMRs are designed for high throughput, ease of replication, and compatibility with commodity cloud storage.

## Official Draft Information

- **Title**: COSE Receipts for MMRs
- **Draft**: draft-bryce-cose-receipts-mmr-profile-00
- **Author**: R. Bryce (Datatrails)
- **Date**: 21 June 2025
- **Expires**: 23 December 2025
- **Status**: Standards Track
- **URL**: https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-00.txt

## Components

### `mmr.ts`
Core MMR algorithms based on Section 9 of the draft:
- `allOnes(pos)` - Check if all bits in position are 1 (corresponds to `all_ones` in draft)
- `mostSigBit(pos)` - Get most significant bit mask (corresponds to `most_sig_bit` in draft)
- `indexHeight(i)` - Calculate height of MMR entry (corresponds to `index_height` in draft)
- `hashPosPair64(pos, a, b)` - Hash position with two values (corresponds to `hash_pospair64` in draft)
- `includedRoot(i, nodeHash, proof)` - Apply proof to compute root (corresponds to `included_root` in draft)

### `mmr_utils.ts`
Utility functions for MMR operations specific to COSE integration:
- `leafDigest(statement, timestamp)` - Compute MMR leaf digest
- `rootAndCnf(statement, mmrReceipt)` - Extract root and CNF from receipt

### `mmr_verifier.ts`
MMR receipt verification following the two-step verification process:
- `verifyMMRReceipt(receipt, signedStatement)` - Complete MMR receipt verification
  - Step 2a: Verify receipt signature using computed root
  - Step 2b: Verify MMR proof structure and components

## Key Features

- **Post-order traversal binary Merkle trees**: MMRs use a specific tree structure optimized for append-only operations
- **High throughput**: Designed for efficient operations at scale
- **Cloud storage compatibility**: Works well with commodity cloud storage solutions
- **COSE integration**: Provides receipts in COSE format for cryptographic verification
- **Verifiable data structure identifier**: Uses identifier `3` for MMR receipts

## Usage

```typescript
import { MMR, MMRUtils, verifyMMRReceipt } from '../src/drafts/draft-bryce-cose-receipts-mmr-profile'

// Verify an MMR receipt
const result = await verifyMMRReceipt(receipt, signedStatement)
console.log('Signature verified:', result.signatureVerified)
console.log('Proof verified:', result.proofVerified)

// Use core MMR functions
const height = MMR.indexHeight(nodeIndex)
const root = MMR.includedRoot(index, nodeHash, proof)
```

## Specification Details

According to the draft specification:

- MMR receipts use verifiable data structure identifier `3`
- Proofs are stored in the unprotected header under `verifiable_data_proofs`
- The MMR uses post-order traversal for efficient append-only operations
- Hash functions follow the `hash_pospair64` algorithm from Section 8.3.1
- Index height calculation follows the algorithm from Section 9.1
- Inclusion proof verification follows the algorithm from Section 5

## Implementation Notes

- This implementation follows the algorithms defined in the official draft specification
- The core MMR functions are implemented as static methods for efficiency
- Error handling is included for invalid proof structures
- The implementation is compatible with COSE Receipt structures
- Both signature and proof verification are supported for comprehensive validation

## Future Considerations

The draft specification notes that hash algorithm agility is desired, starting with SHA-256 but potentially supporting:
- BLAKE2b-256 (used by some referenced implementations)
- SHA3-256
- SHA3-512
- Possibly Keccak and Pedersen

This implementation currently uses SHA-256 as specified in the draft. 