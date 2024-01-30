export type IANACOSEKeyCommonParameter = {
  'Key Type': string
  'Name': string
  'Label': string
  'CBOR Type': string
  Description: string
  Reference: string
}
export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = {
  "undefined": {
    "Key Type": "6",
    "Name": "matrix 2",
    "Label": "-6",
    "CBOR Type": "array (of array of uint)",
    "Description": "NxN Matrix of entries in F_q in column-major form",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021"
  }
};