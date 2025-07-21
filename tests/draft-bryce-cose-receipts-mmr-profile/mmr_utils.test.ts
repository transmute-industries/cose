import * as cbor from '../../src/cbor'
import { MMRUtils } from '../../src/drafts/draft-bryce-cose-receipts-mmr-profile/mmr_utils'
import { MMR } from '../../src/drafts/draft-bryce-cose-receipts-mmr-profile/mmr'
import { header } from '../../src/iana/assignments/cose'
import { cwt_claims } from '../../src/iana/assignments/cwt'
import { draft_headers } from '../../src/iana/requested/cose'

describe('MMR Utils', () => {
    describe('leafDigest', () => {
        it('should compute consistent leaf digest for same inputs', () => {
            // Create a mock statement
            const claims = new Map()
            claims.set(cwt_claims.sub, 'test-subject-123456789012')

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)

            const digest1 = MMRUtils.leafDigest(statement, timestamp)
            const digest2 = MMRUtils.leafDigest(statement, timestamp)

            expect(digest1).toEqual(digest2)
            expect(digest1.length).toBe(32) // SHA-256 output
        })

        it('should produce different digests for different statements', () => {
            const claims1 = new Map()
            claims1.set(cwt_claims.sub, 'test-subject-123456789012')

            const claims2 = new Map()
            claims2.set(cwt_claims.sub, 'different-subject-123456')

            const headerMap1 = new Map()
            headerMap1.set(header.cwt_claims, claims1)

            const headerMap2 = new Map()
            headerMap2.set(header.cwt_claims, claims2)

            const phdr1 = cbor.encode(headerMap1)
            const phdr2 = cbor.encode(headerMap2)

            const statement1 = cbor.encode({ value: [phdr1, {}, new Uint8Array([1, 2, 3, 4])] })
            const statement2 = cbor.encode({ value: [phdr2, {}, new Uint8Array([1, 2, 3, 4])] })

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)

            const digest1 = MMRUtils.leafDigest(statement1, timestamp)
            const digest2 = MMRUtils.leafDigest(statement2, timestamp)

            expect(digest1).not.toEqual(digest2)
        })

        it('should produce different digests for different timestamps', () => {
            const claims = new Map()
            claims.set(cwt_claims.sub, 'test-subject-123456789012')

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            const timestamp1 = new Uint8Array(8)
            new DataView(timestamp1.buffer).setBigUint64(0, BigInt(1234567890), false)

            const timestamp2 = new Uint8Array(8)
            new DataView(timestamp2.buffer).setBigUint64(0, BigInt(1234567891), false)

            const digest1 = MMRUtils.leafDigest(statement, timestamp1)
            const digest2 = MMRUtils.leafDigest(statement, timestamp2)

            expect(digest1).not.toEqual(digest2)
        })

        it('should handle edge cases in subject extraction', () => {
            // Test with exactly 24 character subject
            const claims = new Map()
            claims.set(cwt_claims.sub, '123456789012345678901234') // exactly 24 chars

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)

            expect(() => MMRUtils.leafDigest(statement, timestamp)).not.toThrow()
        })

        it('should handle subjects longer than 24 characters', () => {
            // Test with subject longer than 24 chars (should use first 24)
            const claims = new Map()
            claims.set(cwt_claims.sub, 'this-is-a-very-long-subject-identifier-that-exceeds-24-characters')

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)

            const digest = MMRUtils.leafDigest(statement, timestamp)
            expect(digest.length).toBe(32)
        })

        it('should handle various timestamp values', () => {
            const claims = new Map()
            claims.set(cwt_claims.sub, 'test-subject-123456789012')

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            // Test with zero timestamp
            const timestamp0 = new Uint8Array(8)
            new DataView(timestamp0.buffer).setBigUint64(0, BigInt(0), false)

            // Test with max timestamp
            const timestampMax = new Uint8Array(8)
            new DataView(timestampMax.buffer).setBigUint64(0, BigInt('0xFFFFFFFFFFFFFFFF'), false)

            expect(() => MMRUtils.leafDigest(statement, timestamp0)).not.toThrow()
            expect(() => MMRUtils.leafDigest(statement, timestampMax)).not.toThrow()

            const digest0 = MMRUtils.leafDigest(statement, timestamp0)
            const digestMax = MMRUtils.leafDigest(statement, timestampMax)

            expect(digest0).not.toEqual(digestMax)
        })
    })

    describe('rootAndCnf', () => {
        function createMockMMRReceipt(options: {
            cnf?: any,
            timestamp?: number,
            leafDigest?: Uint8Array,
            mmrIndex?: number,
            proofElements?: Uint8Array[]
        }) {
            const {
                cnf = new Uint8Array([1, 2, 3, 4]),
                timestamp = 1234567890,
                leafDigest = new Uint8Array(32).fill(1),
                mmrIndex = 0,
                proofElements = [new Uint8Array(32).fill(2)]
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

            // Create unprotected header
            const uhdr = new Map()
            uhdr.set(-260, timestamp) // timestamp
            uhdr.set(-259, Array.from(leafDigest)) // leaf digest

            // Create verifiable data proofs
            const inclusionProof = [0, mmrIndex, proofElements] // [proof_type, mmr_index, proof_elements]
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

        function createMockStatement(subject: string = 'test-subject-123456789012') {
            const claims = new Map()
            claims.set(cwt_claims.sub, subject)

            const headerMap = new Map()
            headerMap.set(header.cwt_claims, claims)

            const phdr = cbor.encode(headerMap)
            const statement = cbor.encode({ value: [phdr, {}, new Uint8Array([1, 2, 3, 4])] })

            return statement
        }

        it('should extract root and CNF from valid MMR receipt', () => {
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

            const result = MMRUtils.rootAndCnf(statement, receipt)

            expect(result.cnf).toBeInstanceOf(Uint8Array)
            expect(result.root).toBeInstanceOf(Uint8Array)
            expect(result.root.length).toBe(32) // SHA-256 output
        })

        it('should compute correct root using MMR inclusion proof', () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const leafDigest = MMRUtils.leafDigest(statement, timestamp)

            const mmrIndex = 0
            const proofElements = [new Uint8Array(32).fill(5)]

            const receipt = createMockMMRReceipt({
                leafDigest,
                mmrIndex,
                proofElements
            })

            const result = MMRUtils.rootAndCnf(statement, receipt)

            // Verify the root matches what MMR.includedRoot would compute
            const expectedRoot = MMR.includedRoot(mmrIndex, leafDigest, proofElements)
            expect(result.root).toEqual(expectedRoot)
        })

        it('should throw error when leaf digest does not match', () => {
            const statement = createMockStatement()

            // Use a different leaf digest than what would be computed
            const wrongLeafDigest = new Uint8Array(32).fill(99)

            const receipt = createMockMMRReceipt({
                leafDigest: wrongLeafDigest,
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            expect(() => MMRUtils.rootAndCnf(statement, receipt)).toThrow('Leaf digest does not match header')
        })

        it('should handle different MMR indices correctly', () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const leafDigest = MMRUtils.leafDigest(statement, timestamp)

            const mmrIndices = [0, 1, 3, 7, 15]

            for (const mmrIndex of mmrIndices) {
                const proofElements = [new Uint8Array(32).fill(mmrIndex + 1)]

                const receipt = createMockMMRReceipt({
                    leafDigest,
                    mmrIndex,
                    proofElements
                })

                expect(() => MMRUtils.rootAndCnf(statement, receipt)).not.toThrow()

                const result = MMRUtils.rootAndCnf(statement, receipt)
                const expectedRoot = MMR.includedRoot(mmrIndex, leafDigest, proofElements)
                expect(result.root).toEqual(expectedRoot)
            }
        })

        it('should handle multi-element proofs', () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const leafDigest = MMRUtils.leafDigest(statement, timestamp)

            const mmrIndex = 1
            const proofElements = [
                new Uint8Array(32).fill(10),
                new Uint8Array(32).fill(20),
                new Uint8Array(32).fill(30)
            ]

            const receipt = createMockMMRReceipt({
                leafDigest,
                mmrIndex,
                proofElements
            })

            expect(() => MMRUtils.rootAndCnf(statement, receipt)).not.toThrow()

            const result = MMRUtils.rootAndCnf(statement, receipt)
            const expectedRoot = MMR.includedRoot(mmrIndex, leafDigest, proofElements)
            expect(result.root).toEqual(expectedRoot)
        })

        it('should handle different CNF values', () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const leafDigest = MMRUtils.leafDigest(statement, timestamp)

            const cnfValues = [
                new Uint8Array([1, 2, 3, 4]),
                new Uint8Array([0xFF, 0xEE, 0xDD, 0xCC]),
                new Uint8Array(32).fill(42)
            ]

            for (const cnf of cnfValues) {
                const receipt = createMockMMRReceipt({
                    leafDigest,
                    cnf,
                    mmrIndex: 0,
                    proofElements: [new Uint8Array(32).fill(2)]
                })

                const result = MMRUtils.rootAndCnf(statement, receipt)

                // Verify CNF is properly encoded
                expect(result.cnf).toBeInstanceOf(Uint8Array)

                // Decode and verify it matches the original
                const decodedCnf = cbor.decode(result.cnf)
                expect(new Uint8Array(decodedCnf)).toEqual(cnf)
            }
        })

        it('should handle different timestamp values', () => {
            const statement = createMockStatement()

            const timestamps = [0, 1, 1234567890, 0xFFFFFFFF]

            for (const timestampValue of timestamps) {
                const timestamp = new Uint8Array(8)
                new DataView(timestamp.buffer).setBigUint64(0, BigInt(timestampValue), false)
                const leafDigest = MMRUtils.leafDigest(statement, timestamp)

                const receipt = createMockMMRReceipt({
                    leafDigest,
                    timestamp: timestampValue,
                    mmrIndex: 0,
                    proofElements: [new Uint8Array(32).fill(2)]
                })

                expect(() => MMRUtils.rootAndCnf(statement, receipt)).not.toThrow()
            }
        })

        it('should be deterministic for same inputs', () => {
            const statement = createMockStatement()

            const timestamp = new Uint8Array(8)
            new DataView(timestamp.buffer).setBigUint64(0, BigInt(1234567890), false)
            const leafDigest = MMRUtils.leafDigest(statement, timestamp)

            const receipt = createMockMMRReceipt({
                leafDigest,
                mmrIndex: 0,
                proofElements: [new Uint8Array(32).fill(2)]
            })

            const result1 = MMRUtils.rootAndCnf(statement, receipt)
            const result2 = MMRUtils.rootAndCnf(statement, receipt)

            expect(result1.root).toEqual(result2.root)
            expect(result1.cnf).toEqual(result2.cnf)
        })
    })
}) 