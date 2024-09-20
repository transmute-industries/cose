import { base64url, calculateJwkThumbprint } from "jose";
import { CoseKey } from ".";

import { formatJwk } from "./formatJwk";

import { EC2, Key, KeyTypes } from "../Params";

import * as iana2 from '../../iana/assignments/cose'

import { labels_to_algorithms } from "../../iana/requested/cose";

export const convertCoseKeyToJsonWebKey = async <T>(coseKey: CoseKey): Promise<T> => {
  // todo refactor...
  const kty = coseKey.get(Key.Kty) as number
  // kty EC2
  if (![KeyTypes.EC2].includes(kty)) {
    throw new Error('This library requires does not support the given key type')
  }
  const kid = coseKey.get(Key.Kid)
  const algLabel = coseKey.get(Key.Alg)
  const crv = coseKey.get(EC2.Crv)
  const algName = labels_to_algorithms.get(algLabel as number)
  const crv2 = iana2.label_to_curve.get(crv as number)
  if (!crv2) {
    throw new Error('This library requires does not support the given curve')
  }
  const jwk = {
    kty: 'EC',
    alg: algName,
    crv: crv2
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