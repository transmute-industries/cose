import { MMR } from '../../src/drafts/draft-bryce-cose-receipts-mmr-profile/mmr'

describe('MMR Core Algorithms', () => {
    describe('allOnes', () => {
        it('should return true for numbers with all bits set (powers of 2 minus 1)', () => {
            expect(MMR.allOnes(1)).toBe(true)    // 1 = 0b1
            expect(MMR.allOnes(3)).toBe(true)    // 3 = 0b11
            expect(MMR.allOnes(7)).toBe(true)    // 7 = 0b111
            expect(MMR.allOnes(15)).toBe(true)   // 15 = 0b1111
            expect(MMR.allOnes(31)).toBe(true)   // 31 = 0b11111
            expect(MMR.allOnes(63)).toBe(true)   // 63 = 0b111111
            expect(MMR.allOnes(127)).toBe(true)  // 127 = 0b1111111
            expect(MMR.allOnes(255)).toBe(true)  // 255 = 0b11111111
        })

        it('should return false for numbers without all bits set', () => {
            expect(MMR.allOnes(2)).toBe(false)   // 2 = 0b10
            expect(MMR.allOnes(4)).toBe(false)   // 4 = 0b100
            expect(MMR.allOnes(5)).toBe(false)   // 5 = 0b101
            expect(MMR.allOnes(6)).toBe(false)   // 6 = 0b110
            expect(MMR.allOnes(8)).toBe(false)   // 8 = 0b1000
            expect(MMR.allOnes(9)).toBe(false)   // 9 = 0b1001
            expect(MMR.allOnes(16)).toBe(false)  // 16 = 0b10000
            expect(MMR.allOnes(32)).toBe(false)  // 32 = 0b100000
        })

        it('should handle edge case of 0', () => {
            expect(MMR.allOnes(0)).toBe(false)
        })

        it('should handle large numbers', () => {
            expect(MMR.allOnes(1023)).toBe(true)  // 2^10 - 1
            expect(MMR.allOnes(2047)).toBe(true)  // 2^11 - 1
            expect(MMR.allOnes(4095)).toBe(true)  // 2^12 - 1
            expect(MMR.allOnes(1024)).toBe(false) // 2^10
            expect(MMR.allOnes(2048)).toBe(false) // 2^11
        })
    })

    describe('mostSigBit', () => {
        it('should return the most significant bit mask for powers of 2', () => {
            expect(MMR.mostSigBit(1)).toBe(1)    // 0b1 -> 0b1
            expect(MMR.mostSigBit(2)).toBe(2)    // 0b10 -> 0b10
            expect(MMR.mostSigBit(4)).toBe(4)    // 0b100 -> 0b100
            expect(MMR.mostSigBit(8)).toBe(8)    // 0b1000 -> 0b1000
            expect(MMR.mostSigBit(16)).toBe(16)  // 0b10000 -> 0b10000
            expect(MMR.mostSigBit(32)).toBe(32)  // 0b100000 -> 0b100000
        })

        it('should return the most significant bit mask for non-powers of 2', () => {
            expect(MMR.mostSigBit(3)).toBe(2)    // 0b11 -> 0b10
            expect(MMR.mostSigBit(5)).toBe(4)    // 0b101 -> 0b100
            expect(MMR.mostSigBit(6)).toBe(4)    // 0b110 -> 0b100
            expect(MMR.mostSigBit(7)).toBe(4)    // 0b111 -> 0b100
            expect(MMR.mostSigBit(9)).toBe(8)    // 0b1001 -> 0b1000
            expect(MMR.mostSigBit(15)).toBe(8)   // 0b1111 -> 0b1000
            expect(MMR.mostSigBit(31)).toBe(16)  // 0b11111 -> 0b10000
        })

        it('should handle large numbers', () => {
            expect(MMR.mostSigBit(255)).toBe(128)  // 0b11111111 -> 0b10000000
            expect(MMR.mostSigBit(511)).toBe(256)  // 0b111111111 -> 0b100000000
            expect(MMR.mostSigBit(1023)).toBe(512) // 0b1111111111 -> 0b1000000000
        })
    })

    describe('indexHeight', () => {
        it('should return correct heights for leaf nodes (height 0)', () => {
            // Leaves are at positions where pos (i+1) is a power of 2
            expect(MMR.indexHeight(0)).toBe(0)   // pos=1, leaf
            expect(MMR.indexHeight(1)).toBe(0)   // pos=2, leaf  
            expect(MMR.indexHeight(3)).toBe(0)   // pos=4, leaf
            expect(MMR.indexHeight(4)).toBe(0)   // pos=5, leaf
            expect(MMR.indexHeight(7)).toBe(0)   // pos=8, leaf
            expect(MMR.indexHeight(8)).toBe(0)   // pos=9, leaf
            expect(MMR.indexHeight(15)).toBe(0)  // pos=16, leaf
        })

        it('should return correct heights for internal nodes', () => {
            // Internal nodes have heights > 0
            expect(MMR.indexHeight(2)).toBe(1)   // pos=3, height 1
            expect(MMR.indexHeight(5)).toBe(1)   // pos=6, height 1
            expect(MMR.indexHeight(6)).toBe(2)   // pos=7, height 2
            expect(MMR.indexHeight(9)).toBe(1)   // pos=10, height 1
            expect(MMR.indexHeight(10)).toBe(0)  // pos=11, height 0 (leaf)
            expect(MMR.indexHeight(12)).toBe(1)  // pos=13, height 1
            expect(MMR.indexHeight(13)).toBe(2)  // pos=14, height 2
            expect(MMR.indexHeight(14)).toBe(3)  // pos=15, height 3
        })

        it('should handle a sequence of MMR indices correctly', () => {
            // Test a known MMR sequence with expected heights (based on actual MMR behavior)
            const expectedHeights = [
                0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 4
            ]

            for (let i = 0; i < expectedHeights.length; i++) {
                expect(MMR.indexHeight(i)).toBe(expectedHeights[i])
            }
        })

        it('should handle larger indices', () => {
            expect(MMR.indexHeight(31)).toBe(0)  // pos=32, leaf
            expect(MMR.indexHeight(30)).toBe(4)  // pos=31, high internal node
            expect(MMR.indexHeight(62)).toBe(5)  // pos=63, very high internal node
        })
    })

    describe('hashPosPair64', () => {
        it('should produce consistent hashes for same inputs', () => {
            const pos = 5
            const a = new Uint8Array([1, 2, 3, 4])
            const b = new Uint8Array([5, 6, 7, 8])

            const hash1 = MMR.hashPosPair64(pos, a, b)
            const hash2 = MMR.hashPosPair64(pos, a, b)

            expect(hash1).toEqual(hash2)
            expect(hash1.length).toBe(32) // SHA-256 output length
        })

        it('should produce different hashes for different positions', () => {
            const a = new Uint8Array([1, 2, 3, 4])
            const b = new Uint8Array([5, 6, 7, 8])

            const hash1 = MMR.hashPosPair64(1, a, b)
            const hash2 = MMR.hashPosPair64(2, a, b)

            expect(hash1).not.toEqual(hash2)
        })

        it('should produce different hashes for different input data', () => {
            const pos = 5
            const a1 = new Uint8Array([1, 2, 3, 4])
            const b1 = new Uint8Array([5, 6, 7, 8])
            const a2 = new Uint8Array([1, 2, 3, 5]) // different by one byte
            const b2 = new Uint8Array([5, 6, 7, 8])

            const hash1 = MMR.hashPosPair64(pos, a1, b1)
            const hash2 = MMR.hashPosPair64(pos, a2, b2)

            expect(hash1).not.toEqual(hash2)
        })

        it('should handle empty arrays', () => {
            const pos = 1
            const empty = new Uint8Array([])
            const data = new Uint8Array([1, 2, 3])

            expect(() => MMR.hashPosPair64(pos, empty, empty)).not.toThrow()
            expect(() => MMR.hashPosPair64(pos, empty, data)).not.toThrow()
            expect(() => MMR.hashPosPair64(pos, data, empty)).not.toThrow()
        })

        it('should handle large position values', () => {
            const pos = 0xFFFFFFFF // Large 32-bit value
            const a = new Uint8Array([1, 2, 3, 4])
            const b = new Uint8Array([5, 6, 7, 8])

            expect(() => MMR.hashPosPair64(pos, a, b)).not.toThrow()
        })
    })

    describe('includedRoot', () => {
        it('should return original hash when proof is empty', () => {
            const nodeHash = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
            const emptyProof: Uint8Array[] = []

            const result = MMR.includedRoot(0, nodeHash, emptyProof)
            expect(result).toEqual(nodeHash)
        })

        it('should compute root correctly for simple inclusion proof', () => {
            // Test case: prove inclusion of leaf at index 0
            const leafHash = new Uint8Array(32).fill(1) // Mock leaf hash
            const sibling = new Uint8Array(32).fill(2)  // Mock sibling hash
            const proof = [sibling]

            const root = MMR.includedRoot(0, leafHash, proof)

            // Verify that the root is computed correctly by checking it matches manual calculation
            // Index 0 is a left child (since indexHeight(1) = 0 which is NOT > indexHeight(0) = 0)
            // So parent is at index 0 + 2^(0+1) = 2, position 3, and hash should be H(3 || leafHash || sibling)
            const expectedRoot = MMR.hashPosPair64(3, leafHash, sibling)
            expect(root).toEqual(expectedRoot)
        })

        it('should compute root correctly for multi-level proof', () => {
            // Test case: prove inclusion of leaf at index 1
            const leafHash = new Uint8Array(32).fill(1)
            const sibling1 = new Uint8Array(32).fill(2)
            const sibling2 = new Uint8Array(32).fill(3)
            const proof = [sibling1, sibling2]

            const root = MMR.includedRoot(1, leafHash, proof)

            // The algorithm correctly computes:
            // Step 1: index 1 is right child (indexHeight(2) > indexHeight(1)), move to parent at index 2
            //         root = H(3 || sibling1 || leafHash)
            // Step 2: index 2 is left child (indexHeight(3) <= indexHeight(2)), move to parent at index 2 + 2^(1+1) = 6
            //         root = H(7 || root || sibling2)
            const level1 = MMR.hashPosPair64(3, sibling1, leafHash)
            const expectedRoot = MMR.hashPosPair64(7, level1, sibling2)

            expect(root).toEqual(expectedRoot)
        })

        it('should handle proofs for different indices consistently', () => {
            const hash1 = new Uint8Array(32).fill(1)
            const hash2 = new Uint8Array(32).fill(2)
            const hash3 = new Uint8Array(32).fill(3)

            // Test that including different leaves with appropriate proofs works
            const proof1 = [hash2]
            const proof2 = [hash1]

            const root1 = MMR.includedRoot(0, hash1, proof1) // Right child
            const root2 = MMR.includedRoot(1, hash2, proof2) // Left child

            // Both should produce the same root when proved against each other
            expect(root1).toEqual(root2)
        })

        it('should handle complex MMR structure', () => {
            // Test with a known MMR structure
            const leafHash = new Uint8Array(32).fill(42)
            const siblings = [
                new Uint8Array(32).fill(1),
                new Uint8Array(32).fill(2),
                new Uint8Array(32).fill(3)
            ]

            expect(() => MMR.includedRoot(0, leafHash, siblings)).not.toThrow()
            expect(() => MMR.includedRoot(1, leafHash, siblings)).not.toThrow()
            expect(() => MMR.includedRoot(7, leafHash, siblings)).not.toThrow()
        })

        it('should be deterministic for same inputs', () => {
            const leafHash = new Uint8Array(32).fill(5)
            const proof = [
                new Uint8Array(32).fill(10),
                new Uint8Array(32).fill(20)
            ]

            const result1 = MMR.includedRoot(3, leafHash, proof)
            const result2 = MMR.includedRoot(3, leafHash, proof)

            expect(result1).toEqual(result2)
        })
    })

    describe('MMR integration tests', () => {
        it('should maintain MMR properties across operations', () => {
            // Test that the height calculation and bit operations work together correctly
            for (let i = 0; i < 100; i++) {
                const height = MMR.indexHeight(i)
                expect(height).toBeGreaterThanOrEqual(0)
                expect(typeof height).toBe('number')
                expect(Number.isInteger(height)).toBe(true)
            }
        })

        it('should handle MMR position calculations correctly', () => {
            // Verify the pos = i + 1 relationship used in algorithms
            for (let i = 0; i < 50; i++) {
                const pos = i + 1
                const height = MMR.indexHeight(i)

                // The position should be valid for bit operations
                expect(pos).toBeGreaterThan(0)
                expect(MMR.mostSigBit(pos)).toBeGreaterThan(0)
                expect(typeof MMR.allOnes(pos)).toBe('boolean')
            }
        })

        it('should produce valid hash outputs for all operations', () => {
            const testData1 = new Uint8Array([1, 2, 3, 4])
            const testData2 = new Uint8Array([5, 6, 7, 8])

            for (let pos = 1; pos <= 10; pos++) {
                const hash = MMR.hashPosPair64(pos, testData1, testData2)
                expect(hash).toBeInstanceOf(Uint8Array)
                expect(hash.length).toBe(32)

                // Hash should not be all zeros (extremely unlikely)
                const allZeros = hash.every(byte => byte === 0)
                expect(allZeros).toBe(false)
            }
        })
    })
}) 