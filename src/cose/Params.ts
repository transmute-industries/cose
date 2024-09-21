/* eslint-disable @typescript-eslint/no-explicit-any */

// This module has some helper functions
// that reduce clutter / verbosity
export type HeaderMapEntry = [number, any]
export type HeaderMap = Map<number, any>

export const ProtectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}

export const UnprotectedHeader = (entries: HeaderMapEntry[]) => {
  return new Map<number, any>(entries)
}

// move to iana cbor
export const COSE_Encrypt0 = 16
export const COSE_Sign1 = 18
export const COSE_Encrypt = 96