
import { HeaderMap } from "../../desugar"

export type CoseSign1Structure = [Buffer, HeaderMap, Buffer, Buffer]
export type DecodedToBeSigned = [string, Buffer, Buffer, Buffer]
export type DecodedCoseSign1 = {
  value: CoseSign1Structure
}

export type RequestCoseSign1Signer = {
  remote: {
    sign: (toBeSigned: ArrayBuffer) => Promise<ArrayBuffer>
  }
}

export type RequestCoseSign1 = {
  protectedHeader: HeaderMap,
  unprotectedHeader?: HeaderMap,
  payload: ArrayBuffer,
  externalAAD?: ArrayBuffer
}

export type CoseSign1Bytes = ArrayBuffer

export type CoseSign1Signer = {
  sign: (req: RequestCoseSign1) => Promise<CoseSign1Bytes>
}

export type RequestCoseSign1Verifier = {
  resolver: {
    resolve: (signature: ArrayBuffer) => Promise<any>
  }
}

export type RequestCoseSign1Verify = {
  coseSign1: CoseSign1Bytes,
  externalAAD?: ArrayBuffer
}

export type RequestCoseSign1VerifyDetached = {
  coseSign1: CoseSign1Bytes,
  payload: ArrayBuffer
  externalAAD?: ArrayBuffer
}

export type CoseSign1Verifier = {
  verify: (req: RequestCoseSign1Verify) => Promise<ArrayBuffer>
}

export type RequestCoseSign1DectachedVerify = RequestCoseSign1Verify & {
  payload: ArrayBuffer
}

export type CoseSign1DetachedVerifier = {
  verify: (req: RequestCoseSign1DectachedVerify) => Promise<ArrayBuffer>
}

