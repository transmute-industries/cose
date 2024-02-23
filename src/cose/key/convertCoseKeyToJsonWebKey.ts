import { base64url, calculateJwkThumbprint } from "jose";
import { CoseKey } from ".";


import { IANACOSEAlgorithms } from '../algorithms';
import { IANACOSEEllipticCurves } from '../elliptic-curves';

const algorithms = Object.values(IANACOSEAlgorithms)
const curves = Object.values(IANACOSEEllipticCurves)

import { formatJwk } from "./formatJwk";

export const convertCoseKeyToJsonWebKey = async <T>(coseKey: CoseKey): Promise<T> => {
  const kty = coseKey.get(1) as number
  const kid = coseKey.get(2)
  const alg = coseKey.get(3)
  const crv = coseKey.get(-1)
  // kty EC, kty: EK
  if (![2, 5].includes(kty)) {
    throw new Error('This library requires does not support the given key type')
  }
  const foundAlgorithm = algorithms.find((param) => {
    return param.Value === `${alg}`
  })
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
  const x = coseKey.get(-2) as any
  const y = coseKey.get(-3) as any
  const d = coseKey.get(-4) as any
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