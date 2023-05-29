export type ProtectedHeader = {
  alg: 'ES256' | 'ES384' | 'ES512' | string
  kid?: string
  content_type?: string
}
