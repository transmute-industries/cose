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

export const PayloadLocation = -6801;
export const PayloadPreImageContentType = -6802;
export const PayloadHashAlgorithm = -6800;


export const CWTClaims = 15
export const Type = 16

// https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/
export const Receipts = 394
export const VerifiableDataStructure = 395
export const VerifiableDataProofs = 396

export const VerifiableDataStructures = {
  'RFC9162-Binary-Merkle-Tree': 1
}

// only for RFC9162-Binary-Merkle-Tree
export const VerifiableDataProofTypes = {
  'RFC9162-Inclusion-Proof': -1,
  'RFC9162-Consistency-Proof': -2
}

export const Protected = {

  PartyUIdentity,
  PartyUNonce,
  PartyUOther,
  PartyVIdentity,
  PartyVNonce,
  PartyVOther,
  ContentType,

  Type, // https://datatracker.ietf.org/doc/html/rfc9596
  CWTClaims, // https://datatracker.ietf.org/doc/html/rfc9597

  PayloadHashAlgorithm, // new COSE Hash Envelop
  PayloadPreImageContentType,
  PayloadLocation,

  VerifiableDataStructure,

}


export const Unprotected = {

  Iv: 5,
  Ek: -4, // new from COSE HPKE

  Receipts,
  VerifiableDataProofs
}

export const A128GCM = 1

export const Aead = {
  A128GCM
}


export const Hash = {
  'SHA256': -16
}





export const COSE_Encrypt0 = 16
export const COSE_Sign1 = 18
export const COSE_Encrypt = 96