import crypto from 'crypto'

/**
 * MMR (Merkle Mountain Range) core implementation
 * Based on draft-bryce-cose-receipts-mmr-profile-00
 * https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-00.txt
 */
export class MMR {
    /**
     * Returns true if all bits, starting with the most significant, are 1
     * Corresponds to `all_ones` function in draft Section B.4
     */
    static allOnes(pos: number): boolean {
        const imsb = pos.toString(2).length - 1
        const mask = (1 << (imsb + 1)) - 1
        return pos === mask
    }

    /**
     * Returns the mask for the most significant bit in pos
     * Corresponds to `most_sig_bit` function in draft Section B.2
     */
    static mostSigBit(pos: number): number {
        return 1 << (pos.toString(2).length - 1)
    }

    /**
     * Returns the 0 based height of the mmr entry indexed by i
     * Corresponds to `index_height` function in draft Section 9.1
     * 
     * From the draft:
     * "index_height(i) returns the zero based height g of the node index i"
     * 
     * Algorithm:
     * pos = i + 1
     * while not all_ones(pos):
     *     pos = pos - most_sig_bit(pos) + 1
     * return bit_length(pos) - 1
     */
    static indexHeight(i: number): number {
        // Safeguard against invalid inputs
        if (typeof i !== 'number' || i < 0 || i > 100000000) {
            throw new Error('Invalid MMR index: must be a reasonable positive number')
        }

        // convert the index to a position to take advantage of the bit patterns afforded
        let pos = i + 1
        let iterations = 0
        const maxIterations = 100 // Prevent infinite loops

        while (!MMR.allOnes(pos)) {
            pos = pos - MMR.mostSigBit(pos) + 1
            iterations++

            // Safeguard: prevent infinite loops
            if (iterations > maxIterations) {
                throw new Error(`MMR indexHeight computation runaway for index ${i}`)
            }
        }
        return pos.toString(2).length - 1
    }

    /**
     * Compute the hash of pos || a || b
     * Corresponds to `hash_pospair64` function in draft Section 8.3.1
     * 
     * From the draft:
     * "Returns H(pos || a || b), which is the value for the node identified by index pos - 1"
     * 
     * Algorithm:
     * h = hashlib.sha256()
     * h.update(pos.to_bytes(8, byteorder="big", signed=False))
     * h.update(a)
     * h.update(b)
     * return h.digest()
     */
    static hashPosPair64(pos: number, a: Uint8Array, b: Uint8Array): Uint8Array {
        const h = crypto.createHash('sha256')
        // Encode pos as 8 bytes in big-endian format
        const posBytes = new Uint8Array(8)
        const view = new DataView(posBytes.buffer)
        view.setBigUint64(0, BigInt(pos), false) // false = big-endian
        h.update(posBytes)
        h.update(a)
        h.update(b)
        return new Uint8Array(h.digest())
    }

    /**
     * Apply the proof to nodehash to produce the implied root
     * Corresponds to `included_root` function in draft Section 4.2
     * 
     * From the draft Section 4.2:
     * "Apply the proof to nodehash to produce the implied root"
     * 
     * Algorithm based on the draft specification for inclusion proof verification
     */
    static includedRoot(i: number, nodeHash: Uint8Array, proof: Uint8Array[]): Uint8Array {
        // Safeguards to prevent hangs
        if (typeof i !== 'number' || i < 0 || i > 100000000) {
            throw new Error('Invalid MMR index: must be a reasonable positive number')
        }

        if (proof.length > 100) {
            throw new Error('Proof too large: maximum 100 elements allowed')
        }

        // set `root` to the value whose inclusion is to be proven
        let root = nodeHash

        // set g to the zero based height of i.
        let g = MMR.indexHeight(i)

        // Safeguard: prevent excessive height values
        if (g > 50) {
            throw new Error('MMR height too large: suspicious index value')
        }

        // for each sibling in the proof
        for (const sibling of proof) {
            // Safeguard: validate sibling size
            if (!(sibling instanceof Uint8Array) || sibling.length > 1000) {
                throw new Error('Invalid sibling element in proof')
            }

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

            // Additional safeguard: prevent runaway computation
            if (g > 50) {
                throw new Error('MMR computation runaway: height exceeded safe limits')
            }
        }

        // Return the hash produced. If the path length was zero, the original nodehash is returned
        return root
    }
} 