/* eslint-disable @typescript-eslint/no-explicit-any */

// This module is just just a limited set of the IANA registries, 
// exposed to make Map initialization more readable

export type HeaderMapEntry = [number, any]
export type HeaderMap = Map<number, any>

export const ProtectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}


export const UnprotectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}

export const PartyUIdentity = -21
export const PartyUNonce = -22
export const PartyUOther = -23

export const PartyVIdentity = -24
export const PartyVNonce = -25
export const PartyVOther = -26

export const ContentType = 3




export const CWTClaims = 15
export const Type = 16

// https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/

export const VerifiableDataStructures = {
  'RFC9162-Binary-Merkle-Tree': 1
}

// only for RFC9162-Binary-Merkle-Tree
export const VerifiableDataProofTypes = {
  'RFC9162-Inclusion-Proof': -1,
  'RFC9162-Consistency-Proof': -2
}


export const Unprotected = {

  Iv: 5,
  Ek: -4, // new from COSE HPKE
}

export const A128GCM = 1

export const Aead = {
  A128GCM
}

export const COSE_Encrypt0 = 16
export const COSE_Sign1 = 18
export const COSE_Encrypt = 96