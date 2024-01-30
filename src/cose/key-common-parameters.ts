export type IANACOSEKeyCommonParameter = {
  Name: string
  Label: string
  'CBOR Type': string
  'Value Registry': string
  Description: string
  Reference: string
}
export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = {
  "undefined": {
    "Name": "Base IV",
    "Label": "5",
    "CBOR Type": "bstr",
    "Value Registry": "",
    "Description": "Base IV to be XORed with Partial IVs",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  }
};