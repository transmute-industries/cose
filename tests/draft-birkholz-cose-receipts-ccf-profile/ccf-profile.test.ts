import crypto from 'crypto'
import * as cose from '../../src'

describe('CCF Profile Implementation', () => {
    it('should create and validate CCF leaf', () => {
        const leaf: cose.CCFLeaf = {
            internal_transaction_hash: new Uint8Array(32).fill(1),
            internal_evidence: 'test-evidence',
            data_hash: new Uint8Array(32).fill(2)
        }

        expect(cose.validateCCFLeaf(leaf)).toBe(true)
    })

    it('should create CCF leaf hash', () => {
        const leaf: cose.CCFLeaf = {
            internal_transaction_hash: new Uint8Array(32).fill(1),
            internal_evidence: 'test-evidence',
            data_hash: new Uint8Array(32).fill(2)
        }

        const hashFunction = (data: Uint8Array) => {
            return new Uint8Array(crypto.createHash('sha256').update(data).digest())
        }

        const leafHash = cose.createCCFLeafHash(leaf, hashFunction)
        expect(leafHash.length).toBeGreaterThan(0)
    })

    it('should validate CCF inclusion proof', () => {
        const proof: cose.CCFInclusionProof = {
            leaf: {
                internal_transaction_hash: new Uint8Array(32).fill(1),
                internal_evidence: 'test-evidence',
                data_hash: new Uint8Array(32).fill(2)
            },
            path: [
                {
                    left: true,
                    hash: new Uint8Array(32).fill(3)
                }
            ]
        }

        expect(cose.validateCCFInclusionProof(proof)).toBe(true)
    })

    it('should compute CCF root from proof', () => {
        const proof: cose.CCFInclusionProof = {
            leaf: {
                internal_transaction_hash: new Uint8Array(32).fill(1),
                internal_evidence: 'test-evidence',
                data_hash: new Uint8Array(32).fill(2)
            },
            path: [
                {
                    left: true,
                    hash: new Uint8Array(32).fill(3)
                }
            ]
        }

        const hashFunction = (data: Uint8Array) => {
            return new Uint8Array(crypto.createHash('sha256').update(data).digest())
        }

        const root = cose.computeCCFRoot(proof, hashFunction)
        expect(root.length).toBe(32) // SHA-256 hash size
    })

    it('should extract index from CCF proof', () => {
        const proof: cose.CCFInclusionProof = {
            leaf: {
                internal_transaction_hash: new Uint8Array(32).fill(1),
                internal_evidence: 'test-evidence',
                data_hash: new Uint8Array(32).fill(2)
            },
            path: [
                { left: false, hash: new Uint8Array(32).fill(3) }, // bit 0 = 1
                { left: true, hash: new Uint8Array(32).fill(4) },  // bit 1 = 0
                { left: false, hash: new Uint8Array(32).fill(5) }  // bit 2 = 1
            ]
        }

        const index = cose.extractIndexFromCCFProof(proof)
        expect(index).toBe(5) // binary 101 = decimal 5
    })

    it('should encode and decode CCF leaf', () => {
        const leaf: cose.CCFLeaf = {
            internal_transaction_hash: new Uint8Array(32).fill(1),
            internal_evidence: 'test-evidence',
            data_hash: new Uint8Array(32).fill(2)
        }

        const encoded = cose.encodeCCFLeaf(leaf)
        const decoded = cose.decodeCCFLeaf(encoded)

        expect(decoded.internal_transaction_hash).toEqual(leaf.internal_transaction_hash)
        expect(decoded.internal_evidence).toBe(leaf.internal_evidence)
        expect(decoded.data_hash).toEqual(leaf.data_hash)
    })

    it('should encode and decode CCF inclusion proof', () => {
        const proof: cose.CCFInclusionProof = {
            leaf: {
                internal_transaction_hash: new Uint8Array(32).fill(1),
                internal_evidence: 'test-evidence',
                data_hash: new Uint8Array(32).fill(2)
            },
            path: [
                { left: true, hash: new Uint8Array(32).fill(3) }
            ]
        }

        const encoded = cose.encodeCCFInclusionProof(proof)
        const decoded = cose.decodeCCFInclusionProof(encoded)

        expect(decoded.leaf.internal_transaction_hash).toEqual(proof.leaf.internal_transaction_hash)
        expect(decoded.leaf.internal_evidence).toBe(proof.leaf.internal_evidence)
        expect(decoded.leaf.data_hash).toEqual(proof.leaf.data_hash)
        expect(decoded.path.length).toBe(proof.path.length)
        expect(decoded.path[0].left).toBe(proof.path[0].left)
        expect(decoded.path[0].hash).toEqual(proof.path[0].hash)
    })
}) 