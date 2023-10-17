import { UnprotectedHeaderMap } from './HeaderParameters'

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
