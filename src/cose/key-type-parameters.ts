export type IANACOSEKeyCommonParameter = {
  'Key Type': string
  'Name': string
  'Label': string
  'CBOR Type': string
  Description: string
  Reference: string
}

export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = {
  "-1": {
    "Key Type": "6",
    "Name": "N",
    "Label": "-1",
    "CBOR Type": "uint",
    "Description": "Group and Matrix (NxN) size",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-2": {
    "Key Type": "6",
    "Name": "q",
    "Label": "-2",
    "CBOR Type": "uint",
    "Description": "Finite field F_q",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-4": {
    "Key Type": "6",
    "Name": "matrix 1",
    "Label": "-4",
    "CBOR Type": "array (of array of uint)",
    "Description": "NxN Matrix of entries in F_q in column-major form",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-3": {
    "Key Type": "6",
    "Name": "t-values",
    "Label": "-3",
    "CBOR Type": "array (of uint)",
    "Description": "List of T-values, entries in F_q",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-5": {
    "Key Type": "6",
    "Name": "permutation 1",
    "Label": "-5",
    "CBOR Type": "array (of uint)",
    "Description": "Permutation associated with matrix 1",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-6": {
    "Key Type": "6",
    "Name": "matrix 2",
    "Label": "-6",
    "CBOR Type": "array (of array of uint)",
    "Description": "NxN Matrix of entries in F_q in column-major form",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "-7": {
    "Key Type": "3",
    "Name": "dQ",
    "Label": "-7",
    "CBOR Type": "bstr",
    "Description": "dQ is d mod (q - 1)",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "-8": {
    "Key Type": "3",
    "Name": "qInv",
    "Label": "-8",
    "CBOR Type": "bstr",
    "Description": "qInv is the CRT coefficient q^(-1) mod p",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "-9": {
    "Key Type": "3",
    "Name": "other",
    "Label": "-9",
    "CBOR Type": "array",
    "Description": "other prime infos, an array",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "-10": {
    "Key Type": "3",
    "Name": "r_i",
    "Label": "-10",
    "CBOR Type": "bstr",
    "Description": "a prime factor r_i of n, where i >= 3",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "-11": {
    "Key Type": "3",
    "Name": "d_i",
    "Label": "-11",
    "CBOR Type": "bstr",
    "Description": "d_i = d mod (r_i - 1)",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "-12": {
    "Key Type": "3",
    "Name": "t_i",
    "Label": "-12",
    "CBOR Type": "bstr",
    "Description": "the CRT coefficient t_i = (r_1 * r_2 * ... *\n        r_(i-1))^(-1) mod r_i",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  }
};