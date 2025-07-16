import crypto from 'crypto'
import * as cose from '../src'

/**
 * Example demonstrating COSE Receipts with CCF Profile
 * Based on draft-birkholz-cose-receipts-ccf-profile-04
 */

async function createCCFExample() {
    console.log('=== COSE Receipts with CCF Profile Example ===\n')

    // 1. Create a CCF leaf structure
    console.log('1. Creating CCF leaf structure...')
    const ccfLeaf: cose.CCFLeaf = {
        internal_transaction_hash: new Uint8Array(32).fill(0x01), // 32-byte hash
        internal_evidence: 'ccf-commit-evidence-12345', // CCF commit evidence
        data_hash: new Uint8Array(32).fill(0x02) // 32-byte data hash
    }

    // Validate the leaf
    if (!cose.validateCCFLeaf(ccfLeaf)) {
        throw new Error('Invalid CCF leaf structure')
    }
    console.log('✓ CCF leaf validated successfully')

    // 2. Create a CCF inclusion proof
    console.log('\n2. Creating CCF inclusion proof...')
    const ccfProof: cose.CCFInclusionProof = {
        leaf: ccfLeaf,
        path: [
            { left: true, hash: new Uint8Array(32).fill(0x03) },  // Left sibling
            { left: false, hash: new Uint8Array(32).fill(0x04) }, // Right sibling
            { left: true, hash: new Uint8Array(32).fill(0x05) }   // Another left sibling
        ]
    }

    // Validate the proof
    if (!cose.validateCCFInclusionProof(ccfProof)) {
        throw new Error('Invalid CCF inclusion proof structure')
    }
    console.log('✓ CCF inclusion proof validated successfully')

    // 3. Extract index from proof path
    const index = cose.extractIndexFromCCFProof(ccfProof)
    console.log(`✓ Extracted index from proof: ${index} (binary: ${index.toString(2)})`)

    // 4. Create hash function (SHA-256 for CCF)
    const hashFunction = (data: Uint8Array) => {
        return new Uint8Array(crypto.createHash('sha256').update(data).digest())
    }

    // 5. Compute Merkle root from proof
    console.log('\n3. Computing Merkle root from proof...')
    const computedRoot = cose.computeCCFRoot(ccfProof, hashFunction)
    console.log(`✓ Computed root: ${Buffer.from(computedRoot).toString('hex')}`)

    // 6. Test CBOR encoding/decoding
    console.log('\n4. Testing CBOR encoding/decoding...')

    // Encode and decode leaf
    const encodedLeaf = cose.encodeCCFLeaf(ccfLeaf)
    const decodedLeaf = cose.decodeCCFLeaf(encodedLeaf)
    console.log('✓ Leaf encoding/decoding successful')

    // Encode and decode proof
    const encodedProof = cose.encodeCCFInclusionProof(ccfProof)
    const decodedProof = cose.decodeCCFInclusionProof(encodedProof)
    console.log('✓ Proof encoding/decoding successful')

    // 7. Create cryptographic keys for signing
    console.log('\n5. Creating cryptographic keys...')
    const privateKeyJwk = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
        type: 'application/jwk+json',
        algorithm: 'ES256',
    })
    const publicKeyJwk = cose.public_from_private({
        key: privateKeyJwk,
        type: 'application/jwk+json',
    })
    console.log('✓ Cryptographic keys generated')

    // 8. Create COSE signer and verifier
    console.log('\n6. Creating COSE signer and verifier...')
    const signer = cose.detached.signer({
        remote: cose.crypto.signer({
            privateKeyJwk,
        }),
    })
    const verifier = cose.detached.verifier({
        resolver: {
            resolve: async () => {
                return publicKeyJwk
            },
        },
    })
    console.log('✓ COSE signer and verifier created')

    // 9. Create CCF inclusion receipt
    console.log('\n7. Creating CCF inclusion receipt...')
    try {
        const receipt = await cose.createCCFInclusionReceipt(
            ccfProof,
            signer,
            hashFunction,
            publicKeyJwk
        )
        console.log('✓ CCF inclusion receipt created')
        console.log(`  Receipt size: ${receipt.length} bytes`)

        // 10. Verify the receipt
        console.log('\n8. Verifying CCF inclusion receipt...')
        const verificationResult = await cose.verifyCCFInclusionReceipt(
            receipt,
            hashFunction,
            verifier
        )

        if (verificationResult) {
            console.log('✓ CCF inclusion receipt verified successfully')
        } else {
            console.log('✗ CCF inclusion receipt verification failed')
        }

    } catch (error) {
        console.error('✗ Error creating/verifying receipt:', error)
    }

    // 11. Display CCF-specific constants
    console.log('\n9. CCF Profile Constants:')
    console.log(`  Verifiable Data Structure: ${cose.ccf_verifiable_data_structures.ccf_ledger_sha256}`)
    console.log(`  Proof Type (Inclusion): ${cose.ccf_proof_types.inclusion}`)
    console.log(`  Transparency Map:`, cose.ccf_transparency)

    console.log('\n=== Example completed successfully ===')
}

// Run the example
createCCFExample().catch(console.error) 