import * as cbor from '../../cbor'

// CCF Leaf structure as defined in the draft
export interface CCFLeaf {
    internal_transaction_hash: Uint8Array  // Byte string of size HASH_SIZE(32)
    internal_evidence: string              // Text string of at most 1024 bytes
    data_hash: Uint8Array                  // Byte string of size HASH_SIZE(32)
}

// CCF Proof Element structure
export interface CCFProofElement {
    left: boolean                          // Position of the element
    hash: Uint8Array                       // Hash of the proof element: byte string of size HASH_SIZE(32)
}

// CCF Inclusion Proof structure
export interface CCFInclusionProof {
    leaf: CCFLeaf
    path: CCFProofElement[]
}

// Helper function to get the decoded value
function getDecodedValue(decoded: any): any {
    return decoded.value !== undefined ? decoded.value : decoded
}

// CBOR encoding for CCF Leaf
export function encodeCCFLeaf(leaf: CCFLeaf): Uint8Array {
    const encoded = [
        leaf.internal_transaction_hash,
        leaf.internal_evidence,
        leaf.data_hash
    ]
    return new Uint8Array(cbor.encode(encoded))
}

// CBOR decoding for CCF Leaf
export function decodeCCFLeaf(data: Uint8Array): CCFLeaf {
    const decoded = cbor.decode(data)
    const value = getDecodedValue(decoded)
    return {
        internal_transaction_hash: value[0],
        internal_evidence: value[1],
        data_hash: value[2]
    }
}

// CBOR encoding for CCF Proof Element
export function encodeCCFProofElement(element: CCFProofElement): Uint8Array {
    const encoded = [
        element.left,
        element.hash
    ]
    return new Uint8Array(cbor.encode(encoded))
}

// CBOR decoding for CCF Proof Element
export function decodeCCFProofElement(data: Uint8Array): CCFProofElement {
    const decoded = cbor.decode(data)
    const value = getDecodedValue(decoded)
    return {
        left: value[0],
        hash: value[1]
    }
}

// CBOR encoding for CCF Inclusion Proof
export function encodeCCFInclusionProof(proof: CCFInclusionProof): Uint8Array {
    const encoded = new Map()
    encoded.set(1, encodeCCFLeaf(proof.leaf))
    encoded.set(2, proof.path.map(element => encodeCCFProofElement(element)))
    return new Uint8Array(cbor.encode(encoded))
}

// CBOR decoding for CCF Inclusion Proof
export function decodeCCFInclusionProof(data: Uint8Array | Map<any, any> | any): CCFInclusionProof {
    let value: any
    if (data instanceof Uint8Array) {
        const decoded = cbor.decode(data)
        value = getDecodedValue(decoded)
    } else if (data instanceof Map) {
        value = data
    } else {
        // If it's already decoded, use it directly
        value = data
    }

    // Handle different possible structures
    let leaf: CCFLeaf
    let path: CCFProofElement[]

    // Check if it's a Map structure (keys 1 and 2)
    if (value instanceof Map) {
        const leafRaw = value.get(1)
        const pathRaw = value.get(2)

        if (leafRaw instanceof Uint8Array) {
            leaf = decodeCCFLeaf(leafRaw)
        } else if (Array.isArray(leafRaw)) {
            leaf = {
                internal_transaction_hash: leafRaw[0],
                internal_evidence: leafRaw[1],
                data_hash: leafRaw[2]
            }
        } else {
            throw new Error('decodeCCFInclusionProof: unexpected leaf format in Map')
        }

        if (Array.isArray(pathRaw)) {
            path = pathRaw.map((element: any) => {
                if (element instanceof Uint8Array) {
                    return decodeCCFProofElement(element)
                } else if (Array.isArray(element)) {
                    return {
                        left: element[0],
                        hash: element[1]
                    }
                } else {
                    throw new Error('decodeCCFInclusionProof: unexpected path element format in Map')
                }
            })
        } else {
            throw new Error('decodeCCFInclusionProof: unexpected path format in Map')
        }
    } else if (value.leaf && value.path) {
        // Handle direct object structure with leaf and path properties
        if (value.leaf.internal_transaction_hash && value.leaf.internal_evidence && value.leaf.data_hash) {
            leaf = value.leaf
        } else {
            throw new Error('decodeCCFInclusionProof: invalid leaf structure in object')
        }

        if (Array.isArray(value.path)) {
            path = value.path.map((element: any) => {
                if (element.left !== undefined && element.hash) {
                    return {
                        left: element.left,
                        hash: element.hash
                    }
                } else {
                    throw new Error('decodeCCFInclusionProof: invalid path element structure in object')
                }
            })
        } else {
            throw new Error('decodeCCFInclusionProof: invalid path structure in object')
        }
    } else {
        throw new Error('decodeCCFInclusionProof: unsupported data structure')
    }

    return {
        leaf,
        path
    }
} 