export type IANACOSEKeyCommonParameter = {
  Name: string
  Label: string
  'CBOR Type': string
  'Value Registry': string
  Description: string
  Reference: string
}
export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = {
  "0": {
    "Name": "Reserved",
    "Label": "0",
    "CBOR Type": "",
    "Value Registry": "",
    "Description": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "1": {
    "Name": "kty",
    "Label": "1",
    "CBOR Type": "tstr / int",
    "Value Registry": "COSE Key Types",
    "Description": "Identification of the key type",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "2": {
    "Name": "kid",
    "Label": "2",
    "CBOR Type": "bstr",
    "Value Registry": "",
    "Description": "Key identification value - match to kid in message",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "3": {
    "Name": "alg",
    "Label": "3",
    "CBOR Type": "tstr / int",
    "Value Registry": "COSE Algorithms",
    "Description": "Key usage restriction to this algorithm",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "4": {
    "Name": "key_ops",
    "Label": "4",
    "CBOR Type": "[+ (tstr/int)]",
    "Value Registry": "",
    "Description": "Restrict set of permissible operations",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "5": {
    "Name": "Base IV",
    "Label": "5",
    "CBOR Type": "bstr",
    "Value Registry": "",
    "Description": "Base IV to be XORed with Partial IVs",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "less than -65536": {
    "Name": "Reserved for Private Use",
    "Label": "less than -65536",
    "CBOR Type": "",
    "Value Registry": "",
    "Description": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  },
  "-65536 to -1": {
    "Name": "used for key parameters specific to a single algorithm\n        delegated to the COSE Key Type Parameters registry",
    "Label": "-65536 to -1",
    "CBOR Type": "",
    "Value Registry": "",
    "Description": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9052"
  }
};