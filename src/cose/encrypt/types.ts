import { JsonWebKey } from "../key"

export type JWKS = {
  keys: JsonWebKey[]
}

export type RequestWrapEncryption = {
  aad?: Uint8Array,
  protectedHeader: Map<any, any>
  unprotectedHeader?: Map<any, any>
  plaintext: Uint8Array,
  recipients: {
    keys: any[]
  }
}


export type RequestWrapDecryption = {
  aad?: Uint8Array,
  ciphertext: any,
  recipients: {
    keys: any[]
  }
}


export type RequestDirectEncryption = {
  aad?: Uint8Array,
  protectedHeader: Map<any, any>
  unprotectedHeader?: Map<any, any>
  plaintext: Uint8Array,
  recipients: {
    keys: any[]
  }
}

export type RequestDirectDecryption = {
  aad?: Uint8Array,
  ciphertext: any,
  recipients: {
    keys: any[]
  }
}

