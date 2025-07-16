import * as cbor from '../../cbor'
import { draft_headers } from '../../iana/requested/cose'
import { header, algorithm } from '../../iana/assignments/cose'
import { ProtectedHeader, UnprotectedHeader } from '../../desugar'
import { CCFInclusionProof } from './types'
import { decodeCCFInclusionProof } from './types'
import { computeCCFRoot } from './ccf_proof'
import { validateCCFInclusionProof } from './ccf_proof'
import { DynamicTrustStore, jwkToCoseKey } from './dynamic_trust_store'
import * as cose from '../../index'

/**
 * Verifies a CCF inclusion receipt according to the draft algorithm:
 * 
 * verify_inclusion_receipt(inclusion_receipt):
 *   let label = INCLUSION_PROOF_LABEL
 *   assert(label in inclusion_receipt.unprotected_header)
 *   let proof = inclusion_receipt.unprotected_header[label]
 *   assert(inclusion_receipt.payload == nil)
 *   let payload = compute_root(proof)
 *   return verify_cose(inclusion_receipt, payload)
 */
export async function verifyCCFInclusionReceipt(
    inclusionReceipt: Uint8Array,
    hashFunction: (data: Uint8Array) => Uint8Array,
    verifier?: any // Optional COSE verifier interface
): Promise<boolean> {
    try {
        // Decode the COSE Sign1 structure
        const decoded = cbor.decode(inclusionReceipt)

        // Extract protected and unprotected headers
        const protectedHeader = cbor.decode(decoded.value[0])
        const unprotectedHeader = decoded.value[1]
        const payload = decoded.value[2]

        // Check that payload is null (detached signature)
        if (payload !== null) {
            throw new Error('CCF inclusion receipt must have detached payload')
        }

        // Check for verifiable-data-structure header (must be 2 for CCF)
        const vds = protectedHeader.get(draft_headers.verifiable_data_structure)
        if (vds !== 2) {
            throw new Error(`Invalid verifiable data structure: expected 2 (CCF), got ${vds}`)
        }

        // Extract inclusion proof from unprotected header
        const proofs = unprotectedHeader.get(draft_headers.verifiable_data_proofs)
        if (!proofs || !proofs.get(-1)) {
            throw new Error('Missing inclusion proof in unprotected header')
        }

        const proofData = proofs.get(-1)[0] // Get first inclusion proof
        // Debug output for proofData
        console.log('[DEBUG] proofData type:', typeof proofData, Array.isArray(proofData) ? 'Array' : proofData && proofData.constructor && proofData.constructor.name)
        if (proofData instanceof Uint8Array) {
            console.log('[DEBUG] proofData (Uint8Array):', Buffer.from(proofData).toString('hex').slice(0, 64) + '...')
            try {
                const decodedProof = cbor.decode(proofData)
                console.log('[DEBUG] proofData CBOR-decoded:', decodedProof)
            } catch (e) {
                const err = e instanceof Error ? e : new Error(String(e));
                console.log('[DEBUG] proofData CBOR decode error:', err.message)
            }
        } else {
            console.log('[DEBUG] proofData (raw):', proofData)
        }

        // Fix: decode if buffer and decodes to expected structure, else pass as-is
        let proof: CCFInclusionProof
        if (proofData instanceof Uint8Array) {
            try {
                proof = decodeCCFInclusionProof(proofData)
            } catch (e) {
                const err = e instanceof Error ? e : new Error(String(e));
                console.log('[DEBUG] decodeCCFInclusionProof error:', err.message)
                // Try using as already-decoded
                proof = proofData as any
            }
        } else {
            proof = proofData as any // already decoded
        }

        // Validate the proof structure
        if (!validateCCFInclusionProof(proof)) {
            throw new Error('Invalid CCF inclusion proof structure')
        }

        // Compute the root from the proof
        const computedRoot = computeCCFRoot(proof, hashFunction)

        // If no verifier provided, create one using dynamic trust store
        if (!verifier) {
            const trustStore = new DynamicTrustStore()
            const publicKeyJwk = await trustStore.getKey(inclusionReceipt)

            verifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => {
                        return jwkToCoseKey(publicKeyJwk)
                    }
                }
            })
        }

        // Verify the COSE signature using the computed root as payload
        const verificationResult = await verifier.verify({
            coseSign1: inclusionReceipt,
            payload: computedRoot
        })

        return verificationResult
    } catch (error) {
        console.error('CCF inclusion receipt verification failed:', error)
        return false
    }
}

/**
 * Verifies a CCF receipt with a custom trust store
 */
export async function verifyCCFReceiptWithTrustStore(
    inclusionReceipt: Uint8Array,
    hashFunction: (data: Uint8Array) => Uint8Array,
    trustStore: DynamicTrustStore
): Promise<boolean> {
    try {
        // Get the public key from the trust store
        const publicKeyJwk = await trustStore.getKey(inclusionReceipt)

        // Create verifier with the retrieved key
        const verifier = cose.detached.verifier({
            resolver: {
                resolve: async () => {
                    return jwkToCoseKey(publicKeyJwk)
                }
            }
        })

        // Use the existing verification logic
        return await verifyCCFInclusionReceipt(inclusionReceipt, hashFunction, verifier)
    } catch (error) {
        console.error('CCF receipt verification with trust store failed:', error)
        return false
    }
}

/**
 * Creates a CCF inclusion receipt
 */
export async function createCCFInclusionReceipt(
    proof: CCFInclusionProof,
    signer: any, // COSE signer interface
    hashFunction: (data: Uint8Array) => Uint8Array,
    publicKeyJwk: any
): Promise<Uint8Array> {
    // Validate the proof
    if (!validateCCFInclusionProof(proof)) {
        throw new Error('Invalid CCF inclusion proof structure')
    }

    // Compute the root
    const root = computeCCFRoot(proof, hashFunction)

    // Encode the proof
    const proofData = cbor.encode(proof)

    // Create the receipt
    const receipt = await signer.sign({
        protectedHeader: ProtectedHeader([
            [header.kid, publicKeyJwk.kid],
            [header.alg, algorithm.es256],
            [draft_headers.verifiable_data_structure, 2], // CCF Ledger SHA-256
            [draft_headers.verifiable_data_proofs, -1]    // Inclusion proof
        ]),
        unprotectedHeader: UnprotectedHeader([
            [draft_headers.verifiable_data_proofs, new Map([
                [-1, [proofData]]
            ])]
        ]),
        payload: null // Detached payload
    })

    return receipt
} 