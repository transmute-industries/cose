import { JsonWebKey } from "../key"

export type JWKS = {
  keys: JsonWebKey[]
}

export type RequestWrapEncryption = {
  protectedHeader: Map<any, any>
  unprotectedHeader?: Map<any, any>
  plaintext: Uint8Array,
  recipients: {
    keys: any[]
  }
}


export type RequestWrapDecryption = {
  ciphertext: any,
  recipients: {
    keys: any[]
  }
}


export type RequestDirectEncryption = {
  protectedHeader: Map<any, any>
  unprotectedHeader?: Map<any, any>
  plaintext: Uint8Array,
  recipients: {
    keys: any[]
  }
}

export type RequestDirectDecryption = {
  ciphertext: any,
  recipients: {
    keys: any[]
  }
}

