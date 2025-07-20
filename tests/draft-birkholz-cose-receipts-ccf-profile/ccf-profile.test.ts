import crypto from 'crypto'
import * as cose from '../../src'

describe('CCF Profile Implementation', () => {
    // Test data setup
    const createTestCCFLeaf = (): cose.CCFLeaf => ({
        internal_transaction_hash: new Uint8Array(32).fill(1),
        internal_evidence: 'test-evidence',
        data_hash: new Uint8Array(32).fill(2)
    })

    const createTestCCFProof = (): cose.CCFInclusionProof => ({
        leaf: createTestCCFLeaf(),
        path: [
            { left: true, hash: new Uint8Array(32).fill(3) },
            { left: false, hash: new Uint8Array(32).fill(4) }
        ]
    })

    const createHashFunction = () => (data: Uint8Array) => {
        return new Uint8Array(crypto.createHash('sha256').update(data).digest())
    }

    const createCCFProofData = (proof: cose.CCFInclusionProof): Uint8Array => {
        // Create CCF standard format: CBOR Map with key 1 = leaf, key 2 = path
        const ccfProofMap = new Map()
        ccfProofMap.set(1, [
            proof.leaf.internal_transaction_hash,
            proof.leaf.internal_evidence,
            proof.leaf.data_hash
        ])
        ccfProofMap.set(2, proof.path.map(element => [element.left, element.hash]))
        return cose.cbor.encode(ccfProofMap)
    }

    // Basic CCF functionality tests
    describe('Basic CCF Functionality', () => {
        it('should create and validate CCF leaf', () => {
            const leaf = createTestCCFLeaf()
            expect(cose.validateCCFLeaf(leaf)).toBe(true)
        })

        it('should create CCF leaf hash', () => {
            const leaf = createTestCCFLeaf()
            const hashFunction = createHashFunction()
            const leafHash = cose.createCCFLeafHash(leaf, hashFunction)
            expect(leafHash.length).toBeGreaterThan(0)
        })

        it('should validate CCF inclusion proof', () => {
            const proof = createTestCCFProof()
            expect(cose.validateCCFInclusionProof(proof)).toBe(true)
        })

        it('should compute CCF root from proof', () => {
            const proof = createTestCCFProof()
            const hashFunction = createHashFunction()
            const root = cose.computeCCFRoot(proof, hashFunction)
            expect(root.length).toBe(32) // SHA-256 hash size
        })

        it('should extract index from CCF proof', () => {
            const proof: cose.CCFInclusionProof = {
                leaf: createTestCCFLeaf(),
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
            const leaf = createTestCCFLeaf()
            const encoded = cose.encodeCCFLeaf(leaf)
            const decoded = cose.decodeCCFLeaf(encoded)

            expect(decoded.internal_transaction_hash).toEqual(leaf.internal_transaction_hash)
            expect(decoded.internal_evidence).toBe(leaf.internal_evidence)
            expect(decoded.data_hash).toEqual(leaf.data_hash)
        })

        it('should encode and decode CCF inclusion proof', () => {
            const proof = createTestCCFProof()
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

    // Transparent Statement Verification Tests
    describe('Transparent Statement Verification', () => {
        let issuerKey: any
        let transparencyServiceKey: any
        let issuerSigner: any
        let transparencyServiceSigner: any
        let issuerVerifier: any
        let transparencyServiceVerifier: any
        let statement: Uint8Array
        let signedStatement: Uint8Array
        let ccfProof: cose.CCFInclusionProof
        let ccfReceipt: Uint8Array
        let transparentStatement: Uint8Array

        beforeAll(async () => {
            // Create issuer key and signer
            issuerKey = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
                type: 'application/jwk+json',
                algorithm: 'ES256'
            })
            const issuerPublicKey = cose.public_from_private({
                key: issuerKey,
                type: 'application/jwk+json'
            })

            // Create transparency service key and signer
            transparencyServiceKey = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
                type: 'application/jwk+json',
                algorithm: 'ES256'
            })
            const transparencyServicePublicKey = cose.public_from_private({
                key: transparencyServiceKey,
                type: 'application/jwk+json'
            })

            // Create signers
            issuerSigner = cose.detached.signer({
                remote: cose.crypto.signer({ privateKeyJwk: issuerKey })
            })
            transparencyServiceSigner = cose.detached.signer({
                remote: cose.crypto.signer({ privateKeyJwk: transparencyServiceKey })
            })

            // Create verifiers
            issuerVerifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => issuerPublicKey
                }
            })
            transparencyServiceVerifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => transparencyServicePublicKey
                }
            })

            // Create test statement
            statement = new Uint8Array(Buffer.from('test statement content'))

            // Create signed statement
            signedStatement = await issuerSigner.sign({
                protectedHeader: cose.ProtectedHeader([
                    [cose.header.kid, issuerPublicKey.kid],
                    [cose.header.alg, cose.algorithm.es256],
                    [cose.header.cwt_claims, cose.CWTClaims([
                        [cose.cwt_claims.iss, 'https://issuer.example'],
                        [cose.cwt_claims.sub, 'https://issuer.example/statement@v1.0.0']
                    ])]
                ]),
                payload: statement
            })

            // Create CCF proof with proper data_hash matching the signed statement
            const hashFunction = createHashFunction()
            const signedStatementHash = hashFunction(signedStatement)

            ccfProof = {
                leaf: {
                    internal_transaction_hash: new Uint8Array(32).fill(1),
                    internal_evidence: 'test-evidence',
                    data_hash: signedStatementHash  // Use actual signed statement hash
                },
                path: [
                    { left: true, hash: new Uint8Array(32).fill(3) },
                    { left: false, hash: new Uint8Array(32).fill(4) }
                ]
            }

            // Create CCF receipt
            ccfReceipt = await cose.createCCFInclusionReceipt(
                ccfProof,
                transparencyServiceSigner,
                createHashFunction(),
                transparencyServiceKey,
                'https://transparency.example',
                'https://issuer.example/statement@v1.0.0'
            )

            // Create transparent statement
            transparentStatement = await cose.add_receipt(signedStatement, ccfReceipt)
        })

        it('should verify signed statement (Step 1)', async () => {
            // Step 1: Verify the signed statement
            // For detached signatures, we verify with the original payload
            const verifiedStatement = await issuerVerifier.verify({
                coseSign1: signedStatement,
                payload: statement
            })

            expect(verifiedStatement).toBeDefined()
            expect(verifiedStatement.length).toBeGreaterThan(0)

            // Verify the statement claims
            const decodedStatement = cose.cbor.decode(signedStatement)
            const statementClaims = cose.cbor.decode(decodedStatement.value[0]).get(cose.header.cwt_claims)

            expect(statementClaims.get(cose.cwt_claims.iss)).toBe('https://issuer.example')
            expect(statementClaims.get(cose.cwt_claims.sub)).toBe('https://issuer.example/statement@v1.0.0')
        })

        it('should verify CCF receipt signature (Step 2a)', async () => {
            // Step 2a: Verify the signature on the receipt
            const receiptVerified = await cose.verifyCCFInclusionReceipt(
                ccfReceipt,
                createHashFunction(),
                transparencyServiceVerifier,
                signedStatement
            )

            expect(receiptVerified).toBe(true)
        })

        it('should verify CCF receipt proof (Step 2b)', async () => {
            // Verify the proof structure and computation in the receipt
            const decodedReceipt = cose.cbor.decode(ccfReceipt)
            const protectedHeader = cose.cbor.decode(decodedReceipt.value[0])
            const unprotectedHeader = decodedReceipt.value[1]

            // Verify CCF profile marker
            const vds = protectedHeader.get(cose.draft_headers.verifiable_data_structure)
            expect(vds).toBe(2) // CCF Ledger SHA-256

            // Extract and validate inclusion proof
            const proofs = unprotectedHeader.get(cose.draft_headers.verifiable_data_proofs)
            const proofData = proofs.get(-1)[0]
            const proof = cose.decodeCCFInclusionProof(proofData)

            // Verify proof is valid and computes correctly
            expect(cose.validateCCFInclusionProof(proof)).toBe(true)

            const computedRoot = cose.computeCCFRoot(proof, createHashFunction())
            expect(computedRoot.length).toBe(32) // SHA-256 hash size

            const index = cose.extractIndexFromCCFProof(proof)
            expect(index).toBeGreaterThanOrEqual(0)
        })

        it('should verify complete transparent statement', async () => {
            // Integration test: verify that signed statement + CCF receipt work together

            // Step 1: Verify signed statement
            const verifiedStatement = await issuerVerifier.verify({
                coseSign1: signedStatement,
                payload: statement
            })
            expect(verifiedStatement).toBeDefined()

            // Step 2: Verify receipt integration
            const decodedTransparentStatement = cose.cbor.decode(transparentStatement)
            const receipts = decodedTransparentStatement.value[1].get(cose.draft_headers.receipts) || []

            expect(receipts.length).toBeGreaterThan(0)

            // Verify receipt signature (integration test)
            const receiptVerified = await cose.verifyCCFInclusionReceipt(
                receipts[0],
                createHashFunction(),
                transparencyServiceVerifier,
                signedStatement
            )
            expect(receiptVerified).toBe(true)
        })

        it('should handle multiple receipts in transparent statement', async () => {
            // Test multiple receipts from different transparency services

            // Compute signed statement hash for proper CCF proof
            const hashFunction = createHashFunction()
            const signedStatementHash = hashFunction(signedStatement)

            // Create second transparency service (simplified setup)
            const secondServiceKey = await cose.crypto.key.generate<'ES256', 'application/jwk+json'>({
                type: 'application/jwk+json',
                algorithm: 'ES256'
            })
            const secondServiceSigner = cose.detached.signer({
                remote: cose.crypto.signer({ privateKeyJwk: secondServiceKey })
            })
            const secondServiceVerifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => cose.public_from_private({
                        key: secondServiceKey,
                        type: 'application/jwk+json'
                    })
                }
            })

            // Create and add second receipt with proper data_hash
            const secondProof = {
                leaf: {
                    internal_transaction_hash: new Uint8Array(32).fill(1),
                    internal_evidence: 'test-evidence',
                    data_hash: signedStatementHash  // Use actual signed statement hash
                },
                path: [
                    { left: true, hash: new Uint8Array(32).fill(3) },
                    { left: false, hash: new Uint8Array(32).fill(4) }
                ]
            }

            const secondReceipt = await cose.createCCFInclusionReceipt(
                secondProof,
                secondServiceSigner,
                createHashFunction(),
                secondServiceKey,
                'https://second-transparency.example',
                'https://issuer.example/statement@v1.0.0'
            )

            const multiReceiptStatement = await cose.add_receipt(transparentStatement, secondReceipt)

            // Verify we have multiple receipts
            const decodedMultiReceipt = cose.cbor.decode(multiReceiptStatement)
            const receipts = decodedMultiReceipt.value[1].get(cose.draft_headers.receipts) || []
            expect(receipts.length).toBe(2)

            // Verify both receipts work
            const firstReceiptValid = await cose.verifyCCFInclusionReceipt(
                receipts[0],
                createHashFunction(),
                transparencyServiceVerifier,
                signedStatement
            )
            expect(firstReceiptValid).toBe(true)

            const secondReceiptValid = await cose.verifyCCFInclusionReceipt(
                receipts[1],
                createHashFunction(),
                secondServiceVerifier,
                signedStatement
            )
            expect(secondReceiptValid).toBe(true)
        })

        it('should reject invalid CCF receipts', async () => {
            // Create invalid receipt with wrong verifiable data structure
            const invalidReceipt = await transparencyServiceSigner.sign({
                protectedHeader: cose.ProtectedHeader([
                    [cose.header.kid, transparencyServiceKey.kid],
                    [cose.header.alg, cose.algorithm.es256],
                    [cose.draft_headers.verifiable_data_structure, 1], // Wrong value (should be 2 for CCF)
                    [cose.header.cwt_claims, cose.CWTClaims([
                        [cose.cwt_claims.iss, 'https://transparency.example'],
                        [cose.cwt_claims.sub, 'https://issuer.example/statement@v1.0.0']
                    ])]
                ]),
                unprotectedHeader: cose.UnprotectedHeader([
                    [cose.draft_headers.verifiable_data_proofs, new Map([
                        [-1, [createCCFProofData(ccfProof)]]
                    ])]
                ]),
                payload: null
            })

            // Should reject invalid receipt
            await expect(cose.verifyCCFInclusionReceipt(
                invalidReceipt,
                createHashFunction(),
                transparencyServiceVerifier,
                signedStatement
            )).rejects.toThrow('Invalid verifiable data structure')
        })
    })
}) 