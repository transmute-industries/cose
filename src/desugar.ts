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



export const VerifiableDataStructureProofs = (entries: [number, any][]) => {
  return new Map<number, any>(entries)
}
