
export type ProtectedHeaderMap = Map<any, any>
export type UnprotectedHeaderMap = Map<any, any>

export type CoseSign1Structure = [Buffer, UnprotectedHeaderMap, Buffer, Buffer]
export type DecodedToBeSigned = [string, Buffer, Buffer, Buffer]
export type DecodedCoseSign1 = {
  value: CoseSign1Structure
}

export type SecretKeyJwk = JsonWebKey & { d: string }
export type PublicKeyJwk = Omit<SecretKeyJwk, 'd'>

export type RequestCoseSign1Signer = {
  secretKeyJwk: SecretKeyJwk
}

export type CoseSign1Signer = {
  sign: (req: RequestCoseSign1) => Promise<Buffer>
}

export type RequestCoseSign1 = {
  protectedHeader: ProtectedHeaderMap,
  unprotectedHeader: UnprotectedHeaderMap,
  payload: Buffer,
  externalAAD?: Buffer
}

export type RequestCoseSign1Verifier = { publicKeyJwk: PublicKeyJwk }
export type CoseSign1Bytes = Buffer