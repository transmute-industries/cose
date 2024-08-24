import { base64url, calculateJwkThumbprint } from "jose";
import { CoseKey } from ".";

import { IANACOSEEllipticCurves } from '../elliptic-curves';

const curves = Object.values(IANACOSEEllipticCurves)

import { formatJwk } from "./formatJwk";
import { iana } from "../../iana";
import { EC2, Key, KeyTypes } from "../Params";

export const convertCoseKeyToJsonWebKey = async <T>(coseKey: CoseKey): Promise<T> => {
  const kty = coseKey.get(Key.Kty) as number
  // kty EC2
  if (![KeyTypes.EC2].includes(kty)) {
    throw new Error('This library requires does not support the given key type')
  }
  const kid = coseKey.get(Key.Kid)
  const alg = coseKey.get(Key.Alg)
  const crv = coseKey.get(EC2.Crv)
  const foundAlgorithm = iana["COSE Algorithms"].getByValue(alg as number)
  if (!foundAlgorithm) {
    throw new Error('This library requires keys to use fully specified algorithms')
  }
  const foundCurve = curves.find((param) => {
    return param.Value === `${crv}`
  })
  if (!foundCurve) {
    throw new Error('This library requires does not support the given curve')
  }
  const jwk = {
    kty: 'EC',
    alg: foundAlgorithm.Name,
    crv: foundCurve.Name
  } as any
  const x = coseKey.get(EC2.X) as any
  const y = coseKey.get(EC2.Y) as any
  const d = coseKey.get(EC2.D) as any
  if (x) {
    jwk.x = base64url.encode(x)
  }
  if (y) {
    jwk.y = base64url.encode(y)
  }
  if (d) {
    jwk.d = base64url.encode(d)
  }
  // TODO check lengths for x, y, d
  if (kid && typeof kid === 'string') {
    jwk.kid = kid
  } else {
    jwk.kid = await calculateJwkThumbprint(jwk)
  }
  return formatJwk(jwk) as T
}