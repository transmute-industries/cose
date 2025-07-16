import { CCFInclusionProof, CCFProofElement } from './types'
import { createCCFLeafHash } from './ccf_leaf'

/**
 * Computes the Merkle root from a CCF inclusion proof
 * According to the draft algorithm:
 * 
 * compute_root(proof):
 *   h := proof.leaf.internal-transaction-hash || HASH(proof.leaf.internal-evidence) || proof.leaf.data-hash
 *   for [left, hash] in proof:
 *       h := HASH(hash + h) if left
 *            HASH(h + hash) else
 *   return h
 */
export function computeCCFRoot(
    proof: CCFInclusionProof,
    hashFunction: (data: Uint8Array) => Uint8Array
): Uint8Array {
    // Start with the leaf hash
    let h = createCCFLeafHash(proof.leaf, hashFunction)

    // Process each proof element
    for (const element of proof.path) {
        if (element.left) {
            // h := HASH(hash + h) if left
            const concatenated = new Uint8Array(element.hash.length + h.length)
            concatenated.set(element.hash, 0)
            concatenated.set(h, element.hash.length)
            h = hashFunction(concatenated)
        } else {
            // h := HASH(h + hash) else
            const concatenated = new Uint8Array(h.length + element.hash.length)
            concatenated.set(h, 0)
            concatenated.set(element.hash, h.length)
            h = hashFunction(concatenated)
        }
    }

    return h
}

/**
 * Validates a CCF inclusion proof structure
 */
export function validateCCFInclusionProof(proof: CCFInclusionProof): boolean {
    // Validate the leaf
    if (!proof.leaf) {
        return false
    }

    // Validate the path
    if (!Array.isArray(proof.path)) {
        return false
    }

    // Validate each proof element
    for (const element of proof.path) {
        if (typeof element.left !== 'boolean') {
            return false
        }
        if (!element.hash || element.hash.length !== 32) {
            return false
        }
    }

    return true
}

/**
 * Extracts the index from a CCF inclusion proof path
 * The index is the binary decomposition of the path elements
 */
export function extractIndexFromCCFProof(proof: CCFInclusionProof): number {
    let index = 0
    for (let i = 0; i < proof.path.length; i++) {
        if (!proof.path[i].left) {
            index |= (1 << i)
        }
    }
    return index
} 