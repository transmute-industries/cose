import { ProtectedHeaderMap, UnprotectedHeaderMap } from './HeaderParameters'

export type PublicKeyJwk = {
  alg: string
  kty: string
  crv: string
  x: string
  y: string
}

export type SecretKeyJwk = PublicKeyJwk & {
  d: string
}


export type CoseSign1Structure = [Buffer, UnprotectedHeaderMap, Buffer, Buffer]
export type DecodedToBeSigned = [string, Buffer, Buffer, Buffer]
export type DecodedCoseSign1 = {
  value: CoseSign1Structure
}


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