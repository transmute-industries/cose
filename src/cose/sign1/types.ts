
export type ProtectedHeaderMap = Map<any, any>
export type UnprotectedHeaderMap = Map<any, any>

export type CoseSign1Structure = [Buffer, UnprotectedHeaderMap, Buffer, Buffer]
export type DecodedToBeSigned = [string, Buffer, Buffer, Buffer]
export type DecodedCoseSign1 = {
  value: CoseSign1Structure
}

export type SecretKeyJwk = JsonWebKey & { d: string, kid?: string }
export type PublicKeyJwk = Omit<SecretKeyJwk, 'd'>

export type RequestCoseSign1Signer = {
  remote: {
    sign: (toBeSigned: ArrayBuffer) => Promise<ArrayBuffer>
  }
}

export type RequestCoseSign1 = {
  protectedHeader: ProtectedHeaderMap,
  unprotectedHeader: UnprotectedHeaderMap,
  payload: ArrayBuffer,
  externalAAD?: ArrayBuffer
}

export type CoseSign1Bytes = ArrayBuffer

export type CoseSign1Signer = {
  sign: (req: RequestCoseSign1) => Promise<CoseSign1Bytes>
}

export type RequestCoseSign1Verifier = {
  resolver: {
    resolve: (signature: ArrayBuffer) => Promise<PublicKeyJwk>
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

