export type IANACOSEKeyTypeParameter = {
  'Key Type': string
  'Name': string
  'Label': string
  'CBOR Type': string
  Description: string
  Reference: string
}
export const IANACOSEKeyTypeParameters: Record<string, IANACOSEKeyTypeParameter> = {
  "1-crv": {
    "Key Type": "1",
    "Name": "crv",
    "Label": "-1",
    "CBOR Type": "int / tstr",
    "Description": "EC identifier -- Taken from the \"COSE Elliptic Curves\" registry",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "1-x": {
    "Key Type": "1",
    "Name": "x",
    "Label": "-2",
    "CBOR Type": "bstr",
    "Description": "Public Key",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "1-d": {
    "Key Type": "1",
    "Name": "d",
    "Label": "-4",
    "CBOR Type": "bstr",
    "Description": "Private key",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "2-crv": {
    "Key Type": "2",
    "Name": "crv",
    "Label": "-1",
    "CBOR Type": "int / tstr",
    "Description": "EC identifier -- Taken from the \"COSE Elliptic Curves\" registry",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "2-x": {
    "Key Type": "2",
    "Name": "x",
    "Label": "-2",
    "CBOR Type": "bstr",
    "Description": "x-coordinate",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "2-y": {
    "Key Type": "2",
    "Name": "y",
    "Label": "-3",
    "CBOR Type": "bstr / bool",
    "Description": "y-coordinate",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "2-d": {
    "Key Type": "2",
    "Name": "d",
    "Label": "-4",
    "CBOR Type": "bstr",
    "Description": "Private key",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "3-n": {
    "Key Type": "3",
    "Name": "n",
    "Label": "-1",
    "CBOR Type": "bstr",
    "Description": "the RSA modulus n",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-e": {
    "Key Type": "3",
    "Name": "e",
    "Label": "-2",
    "CBOR Type": "bstr",
    "Description": "the RSA public exponent e",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-d": {
    "Key Type": "3",
    "Name": "d",
    "Label": "-3",
    "CBOR Type": "bstr",
    "Description": "the RSA private exponent d",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-p": {
    "Key Type": "3",
    "Name": "p",
    "Label": "-4",
    "CBOR Type": "bstr",
    "Description": "the prime factor p of n",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-q": {
    "Key Type": "3",
    "Name": "q",
    "Label": "-5",
    "CBOR Type": "bstr",
    "Description": "the prime factor q of n",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-dP": {
    "Key Type": "3",
    "Name": "dP",
    "Label": "-6",
    "CBOR Type": "bstr",
    "Description": "dP is d mod (p - 1)",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-dQ": {
    "Key Type": "3",
    "Name": "dQ",
    "Label": "-7",
    "CBOR Type": "bstr",
    "Description": "dQ is d mod (q - 1)",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-qInv": {
    "Key Type": "3",
    "Name": "qInv",
    "Label": "-8",
    "CBOR Type": "bstr",
    "Description": "qInv is the CRT coefficient q^(-1) mod p",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-other": {
    "Key Type": "3",
    "Name": "other",
    "Label": "-9",
    "CBOR Type": "array",
    "Description": "other prime infos, an array",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-r_i": {
    "Key Type": "3",
    "Name": "r_i",
    "Label": "-10",
    "CBOR Type": "bstr",
    "Description": "a prime factor r_i of n, where i >= 3",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-d_i": {
    "Key Type": "3",
    "Name": "d_i",
    "Label": "-11",
    "CBOR Type": "bstr",
    "Description": "d_i = d mod (r_i - 1)",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "3-t_i": {
    "Key Type": "3",
    "Name": "t_i",
    "Label": "-12",
    "CBOR Type": "bstr",
    "Description": "the CRT coefficient t_i = (r_1 * r_2 * ... *\n        r_(i-1))^(-1) mod r_i",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230"
  },
  "4-k": {
    "Key Type": "4",
    "Name": "k",
    "Label": "-1",
    "CBOR Type": "bstr",
    "Description": "Key Value",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "5-pub": {
    "Key Type": "5",
    "Name": "pub",
    "Label": "-1",
    "CBOR Type": "bstr",
    "Description": "Public key for HSS/LMS hash-based digital signature",
    "Reference": "https://datatracker.ietf.org/doc/RFC8778"
  },
  "6-N": {
    "Key Type": "6",
    "Name": "N",
    "Label": "-1",
    "CBOR Type": "uint",
    "Description": "Group and Matrix (NxN) size",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "6-q": {
    "Key Type": "6",
    "Name": "q",
    "Label": "-2",
    "CBOR Type": "uint",
    "Description": "Finite field F_q",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "6-t-values": {
    "Key Type": "6",
    "Name": "t-values",
    "Label": "-3",
    "CBOR Type": "array (of uint)",
    "Description": "List of T-values, entries in F_q",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "6-matrix 1": {
    "Key Type": "6",
    "Name": "matrix 1",
    "Label": "-4",
    "CBOR Type": "array (of array of uint)",
    "Description": "NxN Matrix of entries in F_q in column-major form",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "6-permutation 1": {
    "Key Type": "6",
    "Name": "permutation 1",
    "Label": "-5",
    "CBOR Type": "array (of uint)",
    "Description": "Permutation associated with matrix 1",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  },
  "6-matrix 2": {
    "Key Type": "6",
    "Name": "matrix 2",
    "Label": "-6",
    "CBOR Type": "array (of array of uint)",
    "Description": "NxN Matrix of entries in F_q in column-major form",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  }
};