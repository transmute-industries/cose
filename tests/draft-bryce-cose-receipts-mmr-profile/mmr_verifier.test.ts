import * as cbor from '../../src/cbor'
import { verifyMMRReceipt } from '../../src/drafts/draft-bryce-cose-receipts-mmr-profile/mmr_verifier'
import { MMRUtils } from '../../src/drafts/draft-bryce-cose-receipts-mmr-profile/mmr_utils'
import { header } from '../../src/iana/assignments/cose'
import { cwt_claims } from '../../src/iana/assignments/cwt'
import { draft_headers } from '../../src/iana/requested/cose'

describe('MMR Verifier (Essential Tests)', () => {
    function createMockStatement(subject: string = 'test-subject-123456789012') {
        const claims = new Map()
        claims.set(cwt_claims.sub, subject)

        const headerMap = new Map()
        headerMap.set(header.cwt_claims, claims)

        const phdr = cbor.encode(headerMap)
        const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

        return statement
    }

    function createMockMMRReceipt(options: {
        cnf?: any,
        timestamp?: number,
        leafDigest?: Uint8Array,
        mmrIndex?: number,
        proofElements?: Uint8Array[],
        vds?: number,
        invalidProofStructure?: boolean
    }) {
        const {
            cnf = new Uint8Array([1, 2, 3, 4]),
            timestamp = 1234567890,
            leafDigest = new Uint8Array(32).fill(1),
            mmrIndex = 0,
            proofElements = [new Uint8Array(32).fill(2)],
            vds = 3, // MMR verifiable data structure identifier
            invalidProofStructure = false
        } = options

        // Create CNF structure
        const cnfMap = new Map()
        cnfMap.set(1, cnf)

        // Create claims
        const claims = new Map()
        claims.set(cwt_claims.cnf, cnfMap)

        // Create protected header
        const phdr = new Map()
        phdr.set(header.cwt_claims, claims)
        phdr.set(draft_headers.verifiable_data_structure, vds)

        // Create unprotected header
        const uhdr = new Map()
        uhdr.set(-260, timestamp) // timestamp
        uhdr.set(-259, Array.from(leafDigest)) // leaf digest

        // Create verifiable data proofs
        let inclusionProof
        if (invalidProofStructure) {
            inclusionProof = [0] // Invalid structure (missing elements)
        } else {
            inclusionProof = [0, mmrIndex, proofElements] // [proof_type, mmr_index, proof_elements]
        }

        const vdProofs = new Map()
        vdProofs.set(-1, [inclusionProof])
        uhdr.set(draft_headers.verifiable_data_proofs, vdProofs)

        // Create receipt structure [protected, unprotected, payload, signature]
        const receipt = {
            value: [
                cbor.encode(phdr),
                uhdr,
                null, // payload
                new Uint8Array([0x11, 0x22, 0x33, 0x44]) // mock signature
            ]
        }

        return cbor.encode(receipt)
    }

    describe('verifyMMRReceipt (Core Tests)', () => {
        it('should return proof verified true for valid MMR receipt structure', async () => {
            const statement = createMockStatement()

            // Calculate expected leaf digest
            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(true)
            expect(result.error).toBeUndefined()
        })

        it('should return error for invalid verifiable data structure', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                vds: 1, // Wrong VDS (should be 3 for MMR)
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Invalid verifiable data structure: expected 3 (MMR), got 1')
        })

        it('should return error for invalid MMR proof structure', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                invalidProofStructure: true
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Invalid MMR index: must be a reasonable positive number')
        })

        it('should handle signature verification failure gracefully', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            // Signature verification will fail with mock data, but proof structure should be valid
            expect(result.signatureVerified).toBe(false)
            expect(result.proofVerified).toBe(true)
        })

        it('should validate MMR proof components', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            // Test with invalid MMR index (string instead of number)
            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                mmrIndex: 'invalid' as any,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Invalid MMR index: must be a reasonable positive number')
        })

        it('should validate proof elements are arrays', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            // Test with invalid proof elements (not an array)
            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                mmrIndex: 0,
                proofElements: 'invalid' as any
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Invalid or oversized proof elements array')
        })

        it('should handle leaf digest mismatch in rootAndCnf', async () => {
            const statement = createMockStatement()

            // Use wrong leaf digest
            const wrongLeafDigest = new Uint8Array(32).fill(99)

            const receipt = createMockMMRReceipt({
                leafDigest: wrongLeafDigest,
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.signatureVerified).toBe(false)
            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Leaf digest does not match header')
        })

        it('should handle malformed CBOR gracefully', async () => {
            const statement = createMockStatement()
            const malformedReceipt = new Uint8Array([0xFF, 0xFE, 0xFD]) // Invalid CBOR

            const result = await verifyMMRReceipt(malformedReceipt, statement)

            expect(result.signatureVerified).toBe(false)
            expect(result.proofVerified).toBe(false)
            expect(result.error).toBeDefined()
        })

        it('should handle one invalid VDS value', async () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const expectedLeafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest: expectedLeafDigest,
                vds: 1, // Invalid VDS (should be 3 for MMR)
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result = await verifyMMRReceipt(receipt, statement)

            expect(result.proofVerified).toBe(false)
            expect(result.error).toContain('Invalid verifiable data structure')
        })
    })
}) 