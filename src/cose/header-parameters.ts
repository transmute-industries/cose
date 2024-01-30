export type IANACOSEHeaderParameter = {
    Name: string
    Label: string
    'Value Type': string
    'Value Registry': string
    Description: string
    Reference: string
  }
  export const IANACOSEHeaderParameters: Record<string, IANACOSEHeaderParameter> = {
  "undefined": {
    "Name": "CUPHOwnerPubKey",
    "Label": "257",
    "Value Type": "array",
    "Value Registry": "",
    "Description": "Public Key",
    "Reference": "[FIDO Device Onboard Specification]"
  }
};