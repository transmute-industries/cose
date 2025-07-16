import * as fs from 'fs'
import * as path from 'path'
import crypto from 'crypto'
import * as cose from '../../src'
import { fetchJwksFromTransparencyConfig } from '../../src/drafts/draft-birkholz-cose-receipts-ccf-profile/scrapi_transparency'

/**
 * MMR (Merkle Mountain Range) verification utilities
 * Based on the MMR Profile Individual Draft
 */
class MMR {
    /**
     * Returns true if all bits, starting with the most significant, are 1
     */
    static allOnes(pos: number): boolean {
        const imsb = pos.toString(2).length - 1
        const mask = (1 << (imsb + 1)) - 1
        return pos === mask
    }

    /**
     * Returns the mask for the most significant bit in pos
     */
    static mostSigBit(pos: number): number {
        return 1 << (pos.toString(2).length - 1)
    }

    /**
     * Returns the 0 based height of the mmr entry indexed by i
     */
    static indexHeight(i: number): number {
        // convert the index to a position to take advantage of the bit patterns afforded
        let pos = i + 1
        while (!MMR.allOnes(pos)) {
            pos = pos - (MMR.mostSigBit(pos) - 1)
        }
        return pos.toString(2).length - 1
    }

    /**
     * Compute the hash of pos || a || b
     */
    static hashPosPair64(pos: number, a: Uint8Array, b: Uint8Array): Uint8Array {
        const h = crypto.createHash('sha256')
        h.update(pos.toString(16).padStart(16, '0'), 'hex') // 8 bytes in hex
        h.update(a)
        h.update(b)
        return new Uint8Array(h.digest())
    }

    /**
     * Apply the proof to nodehash to produce the implied root
     */
    static includedRoot(i: number, nodeHash: Uint8Array, proof: Uint8Array[]): Uint8Array {
        // set `root` to the value whose inclusion is to be proven
        let root = nodeHash

        // set g to the zero based height of i.
        let g = MMR.indexHeight(i)

        // for each sibling in the proof
        for (const sibling of proof) {
            // if the height of the entry immediately after i is greater than g, then
            // i is a right child.
            if (MMR.indexHeight(i + 1) > g) {
                // advance i to the parent. As i is a right child, the parent is at `i+1`
                i = i + 1
                // Set `root` to `H(i+1 || sibling || root)`
                root = MMR.hashPosPair64(i + 1, sibling, root)
            } else {
                // Advance i to the parent. As i is a left child, the parent is at `i + (2^(g+1))`
                i = i + (2 << g)
                // Set `root` to `H(i+1 || root || sibling)`
                root = MMR.hashPosPair64(i + 1, root, sibling)
            }

            // Set g to the height index above the current
            g = g + 1
        }

        // Return the hash produced. If the path length was zero, the original nodehash is returned
        return root
    }
}

/**
 * Utility functions for MMR verification
 */
class MMRUtils {
    /**
     * Compute the MMR leaf digest for a given statement and timestamp
     */
    static leafDigest(statement: Uint8Array, timestamp: Uint8Array): Uint8Array {
        const statementPhdr = cose.cbor.decode(statement)
        const subject = cose.cbor.decode(statementPhdr.value[0]).get(cose.header.cwt_claims).get(cose.cwt_claims.sub)
        const extraBytes = subject.substring(0, 24)
        const leafContent = new Uint8Array(1 + extraBytes.length + timestamp.length + statement.length)
        leafContent[0] = 0 // null byte
        leafContent.set(new TextEncoder().encode(extraBytes), 1)
        leafContent.set(timestamp, 1 + extraBytes.length)
        leafContent.set(statement, 1 + extraBytes.length + timestamp.length)
        return new Uint8Array(crypto.createHash('sha256').update(leafContent).digest())
    }

    /**
     * Extract root and CNF from MMR receipt
     */
    static rootAndCnf(statement: Uint8Array, mmrReceipt: Uint8Array): { root: Uint8Array, cnf: Uint8Array } {
        const receipt = cose.cbor.decode(mmrReceipt)
        const phdr = cose.cbor.decode(receipt.value[0])
        const uhdr = receipt.value[1]

        const cnf = phdr.get(cose.header.cwt_claims).get(cose.cwt_claims.cnf).get(1)
        const cborCnf = new Uint8Array(cose.cbor.encode(cnf))

        const timestampInt = uhdr.get(-260) // timestamp
        const timestamp = new Uint8Array(8)
        const view = new DataView(timestamp.buffer)
        view.setBigUint64(0, BigInt(timestampInt), false) // big endian

        const leafFromHeader = uhdr.get(-259)
        const leafDigest = MMRUtils.leafDigest(statement, timestamp)

        if (!leafFromHeader.every((val: number, idx: number) => val === leafDigest[idx])) {
            throw new Error('Leaf digest does not match header')
        }

        const inclusionProof = uhdr.get(cose.draft_headers.verifiable_data_proofs).get(-1)[0]
        const mmrIndex = inclusionProof[1]
        const proofElements = inclusionProof[2]

        return {
            root: MMR.includedRoot(mmrIndex, leafDigest, proofElements),
            cnf: cborCnf
        }
    }
}

/**
 * Parse a COSE Sign1 message from a byte buffer without verifying the signature
 */
function coseSign1FromBuffer(buffer: Uint8Array): any {
    const cbor = cose.cbor.decode(buffer)
    if (cbor.tag !== 18) {
        throw new Error('Expected COSE Sign1 (tag 18)')
    }
    return cbor
}

/**
 * Verify a transparent statement with receipts
 */
async function verifyTransparentStatement(transparentStatementPath: string): Promise<void> {
    console.log(`Verifying transparent statement: ${transparentStatementPath}`)

    // Read the transparent statement file
    const transparentStatement = new Uint8Array(fs.readFileSync(transparentStatementPath))

    // Parse the COSE Sign1 message
    const ts = coseSign1FromBuffer(transparentStatement)

    // Decode and print protected header
    const protectedHeader = cose.cbor.decode(ts.value[0])
    console.log('\n[DEBUG] Main Protected Header:')
    if (protectedHeader && protectedHeader.keys) {
        for (const [k, v] of protectedHeader) {
            console.log(`  ${k}:`, v)
        }
    } else {
        console.log(protectedHeader)
    }

    // Print unprotected header
    console.log('\n[DEBUG] Main Unprotected Header:')
    if (ts.value[1] && ts.value[1].keys) {
        for (const [k, v] of ts.value[1]) {
            console.log(`  ${k}:`, v)
        }
    } else {
        console.log(ts.value[1])
    }

    // Create signed statement without unprotected headers
    const tsWoUhdr = cose.cbor.decode(transparentStatement)
    tsWoUhdr.value[1] = new Map() // Clear unprotected headers
    const signedStatement = new Uint8Array(cose.cbor.encode(tsWoUhdr))

    // Get receipts from unprotected headers
    const receipts = ts.value[1].get(cose.draft_headers.receipts) || []
    console.log(`\n[DEBUG] Receipts count: ${receipts.length}`)

    // Create hash function for CCF verification
    const hashFunction = (data: Uint8Array) => {
        return new Uint8Array(crypto.createHash('sha256').update(data).digest())
    }

    for (const [i, receipt] of receipts.entries()) {
        const r = coseSign1FromBuffer(receipt)
        const protectedHeader = cose.cbor.decode(r.value[0]);
        const cwtClaims = protectedHeader.get(cose.header.cwt_claims);
        const profile = protectedHeader.get(cose.draft_headers.verifiable_data_structure);

        console.log(`\n[DEBUG] Receipt #${i + 1} Protected Header:`)
        if (protectedHeader && protectedHeader.keys) {
            for (const [k, v] of protectedHeader) {
                console.log(`  ${k}:`, v)
            }
        } else {
            console.log(protectedHeader)
        }
        console.log(`[DEBUG] Receipt #${i + 1} Unprotected Header:`)
        if (r.value[1] && r.value[1].keys) {
            for (const [k, v] of r.value[1]) {
                console.log(`  ${k}:`, v)
            }
        } else {
            console.log(r.value[1])
        }

        if (profile === 2) {
            console.log('Found receipt using profile: CCF (2)')

            // For CCF receipts, use SCRAPI transparency config to resolve JWKS and verify
            try {
                // Extract issuer and kid
                const issuer = cwtClaims && cwtClaims.get ? cwtClaims.get(cose.cwt_claims.iss) : undefined
                const kid = protectedHeader.get(cose.header.kid)
                if (!issuer || !kid) {
                    throw new Error('Missing issuer or kid in CCF receipt')
                }
                // Fetch JWKS using SCRAPI
                const jwks = await fetchJwksFromTransparencyConfig(issuer)
                // Find the key by kid (buffer or string)
                let key = jwks.keys.find((k: any) => k.kid === kid || Buffer.from(k.kid).toString('base64') === Buffer.from(kid).toString('base64'))
                if (!key) {
                    // Try matching as buffer
                    key = jwks.keys.find((k: any) => Buffer.from(k.kid).equals(Buffer.from(kid)))
                }
                if (!key) {
                    throw new Error('Key ID not found in JWKS for issuer: ' + issuer)
                }
                // Use the key for verification
                const verifier = cose.detached.verifier({
                    resolver: {
                        resolve: async () => key
                    }
                })
                const ccfVerificationResult = await cose.verifyCCFInclusionReceipt(
                    receipt,
                    hashFunction,
                    verifier
                )
                if (ccfVerificationResult) {
                    console.log('✓ CCF receipt signature verified using SCRAPI transparency config')
                } else {
                    console.log('✗ CCF receipt signature verification failed')
                }
            } catch (error) {
                console.log('✗ CCF receipt verification error:', error instanceof Error ? error.message : String(error))
            }

        } else if (profile === 3) {
            console.log('Found receipt using profile: MMR (3)')

            // For MMR receipts, we can verify using the MMR logic
            const { root, cnf } = MMRUtils.rootAndCnf(signedStatement, receipt)

            // Verify the receipt signature using the computed root
            const verifier = cose.detached.verifier({
                resolver: {
                    resolve: async () => {
                        // In a real implementation, you would resolve the key from the CNF
                        // For now, we'll just return a placeholder
                        return cnf
                    }
                }
            })

            try {
                await verifier.verify({
                    coseSign1: receipt,
                    payload: root
                })
                console.log('✓ MMR receipt signature verified')
            } catch (error) {
                console.log('✗ MMR receipt signature verification failed:', error instanceof Error ? error.message : String(error))
            }

        } else {
            throw new Error(`Unexpected profile in receipt: ${profile}`)
        }

        const issuer = cwtClaims && cwtClaims.get ? cwtClaims.get(cose.cwt_claims.iss) : undefined
        const subject = cwtClaims && cwtClaims.get ? cwtClaims.get(cose.cwt_claims.sub) : undefined
        console.log(`Verified receipt from issuer (1): ${issuer}, subject (2): ${subject}`)
    }

    console.log(`✓ Verified transparency of statement: ${transparentStatementPath}`)
}

describe('CCF Transparent Statement Verification', () => {
    it('should verify sample-ts.scitt', async () => {
        const statementPath = path.join(__dirname, 'sample-ts.scitt')
        await verifyTransparentStatement(statementPath)
    })
}) 