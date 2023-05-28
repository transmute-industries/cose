export type CoseVerifier = {
  verify: (message: Uint8Array) => Promise<Uint8Array>
}
