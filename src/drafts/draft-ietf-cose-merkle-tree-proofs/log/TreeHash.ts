export const empty_bytes = new Uint8Array()
export const leaf_prefix = new Uint8Array([0])
export const intermediate_prefix = new Uint8Array([1])

export function concat(a1: Uint8Array, a2: Uint8Array): Uint8Array {
  // sum of individual array lengths
  const mergedArray = new Uint8Array(a1.length + a2.length)
  mergedArray.set(a1)
  mergedArray.set(a2, a1.length)
  return mergedArray
}

export function to_hex(bytes: Uint8Array) {
  return bytes.reduce(
    (str: string, byte: number) => str + byte.toString(16).padStart(2, '0'),
    '',
  )
}

export function verify_match(root1: Uint8Array, root2: Uint8Array) {
  return to_hex(root1) === to_hex(root2)
}

export class TreeHash {
  constructor(public hash: (data: Uint8Array) => Uint8Array, public hash_size: number) { }
  empty_root() {
    return this.hash(empty_bytes)
  }
  hash_leaf(leaf: Uint8Array) {
    return this.hash(concat(leaf_prefix, leaf))
  }
  hash_children(left: Uint8Array, right: Uint8Array) {
    return this.hash(concat(intermediate_prefix, concat(left, right)))
  }
}