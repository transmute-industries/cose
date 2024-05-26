// This module is just just a limited set of the IANA registries, 
// exposed to make Map initialization more readable

import { IANACOSEKeyCommonParameters } from "./key-common-parameters"
import * as requested from './requested-assignment'

export type HeaderMapEntry = [number, any]
export type HeaderMap = Map<number, any>

export const ProtectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}


export const UnprotectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}

export const HeaderParameters = {
  Alg: 1,
  Epk: -1,
  Kid: 4,
  X5t: 34
}

export const PartyUIdentity = -21
export const PartyUNonce = -22
export const PartyUOther = -23

export const PartyVIdentity = -24
export const PartyVNonce = -25
export const PartyVOther = -26

export const ContentType = 3

export const ProofType = -111


export const Protected = {
  ...HeaderParameters,
  PartyUIdentity,
  PartyUNonce,
  PartyUOther,
  PartyVIdentity,
  PartyVNonce,
  PartyVOther,
  ContentType,
  ProofType // new from COSE Merkle Tree Proofs
}

export const Unprotected = {
  ...HeaderParameters,
  Iv: 5,
  Ek: -4 // new from COSE HPKE
}

export const A128GCM = 1

export const Aead = {
  A128GCM
}

export const Signature = {
  'ES256': -7
}

export const Receipt = {
  Inclusion: 1
}


export const KeyAgreement = {
  'ECDH-ES+HKDF-256': -25
}
export const KeyAgreementWithKeyWrap = {
  'ECDH-ES+A128KW': -29
}

export const KeyWrap = {
  A128KW: -3
}


export const EC2 = 2

export const KeyType = {
  EC2,
  ['ML-KEM']: requested.KeyTypes['ML-KEM']
}

export const Epk = {
  Kty: 1,
  Crv: -1,
  Alg: 3
}

export const Curve = {
  P256: 1,
}

export const Key = {
  Type: parseInt(IANACOSEKeyCommonParameters['1'].Label, 10),
  Algorithm: parseInt(IANACOSEKeyCommonParameters['3'].Label, 10)
}

export const KeyTypeAlgorithms = {
  ['ML-KEM']: {
    ['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']: requested.Algorithms['HPKE-Base-ML-KEM-768-SHA256-AES128GCM'],
    ['ML-KEM-768']: requested.Algorithms['ML-KEM-768']
  }
}

export const KeyTypeParameters = {
  ['ML-KEM']: {
    Public: -1,
    Secret: -2,
  },
  ['EC2']: {
    Curve: -1,
    PublicX: -2,
    PublicY: -3,
    Secret: -4,
  }
}


export const Direct = {
  'HPKE-Base-P256-SHA256-AES128GCM': 35,
  'HPKE-Base-ML-KEM-768-SHA256-AES128GCM': KeyTypeAlgorithms['ML-KEM']['HPKE-Base-ML-KEM-768-SHA256-AES128GCM']
}

export const COSE_Encrypt0 = 16
export const COSE_Sign1 = 18
export const COSE_Encrypt = 96


