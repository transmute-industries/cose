import { CCFLeaf } from './types'

/**
 * Creates a CCF leaf hash from the leaf components
 * According to the draft, the leaf hash is computed as:
 * h := proof.leaf.internal-transaction-hash || HASH(proof.leaf.internal-evidence) || proof.leaf.data-hash
 */
export function createCCFLeafHash(
    leaf: CCFLeaf,
    hashFunction: (data: Uint8Array) => Uint8Array
): Uint8Array {
    // Convert internal_evidence string to Uint8Array
    const evidenceBytes = new TextEncoder().encode(leaf.internal_evidence)

    // Hash the internal evidence
    const evidenceHash = hashFunction(evidenceBytes)

    // Concatenate: internal-transaction-hash || HASH(internal-evidence) || data-hash
    const concatenated = new Uint8Array(
        leaf.internal_transaction_hash.length +
        evidenceHash.length +
        leaf.data_hash.length
    )

    let offset = 0
    concatenated.set(leaf.internal_transaction_hash, offset)
    offset += leaf.internal_transaction_hash.length
    concatenated.set(evidenceHash, offset)
    offset += evidenceHash.length
    concatenated.set(leaf.data_hash, offset)

    return concatenated
}

/**
 * Validates a CCF leaf structure
 */
export function validateCCFLeaf(leaf: CCFLeaf): boolean {
    // Check internal_transaction_hash size (must be 32 bytes)
    if (leaf.internal_transaction_hash.length !== 32) {
        return false
    }

    // Check internal_evidence size (must be 1-1024 bytes)
    if (leaf.internal_evidence.length < 1 || leaf.internal_evidence.length > 1024) {
        return false
    }

    // Check data_hash size (must be 32 bytes)
    if (leaf.data_hash.length !== 32) {
        return false
    }

    return true
} 