export type IANACOSEEllipticCurve = {
  Name: string
  Value: string
  'Key Type': string
  Description: string
  'Change Controller': string
  Reference: string
  Recommended: string
}
export const IANACOSEEllipticCurves: Record<string, IANACOSEEllipticCurve> = {
  "0": {
    "Name": "Reserved",
    "Value": "0",
    "Key Type": "",
    "Description": "",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "No"
  },
  "Integer values less than -65536": {
    "Name": "Reserved for Private Use",
    "Value": "Integer values less than -65536",
    "Key Type": "",
    "Description": "",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "No"
  },
  "-65536 to -1": {
    "Name": "Unassigned",
    "Value": "-65536 to -1",
    "Key Type": "",
    "Description": "",
    "Change Controller": "",
    "Reference": "",
    "Recommended": ""
  },
  "EC2-P-256": {
    "Name": "P-256",
    "Value": "1",
    "Key Type": "EC2",
    "Description": "NIST P-256 also known as secp256r1",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "EC2-P-384": {
    "Name": "P-384",
    "Value": "2",
    "Key Type": "EC2",
    "Description": "NIST P-384 also known as secp384r1",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "EC2-P-521": {
    "Name": "P-521",
    "Value": "3",
    "Key Type": "EC2",
    "Description": "NIST P-521 also known as secp521r1",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "OKP-X25519": {
    "Name": "X25519",
    "Value": "4",
    "Key Type": "OKP",
    "Description": "X25519 for use w/ ECDH only",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "OKP-X448": {
    "Name": "X448",
    "Value": "5",
    "Key Type": "OKP",
    "Description": "X448 for use w/ ECDH only",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "OKP-Ed25519": {
    "Name": "Ed25519",
    "Value": "6",
    "Key Type": "OKP",
    "Description": "Ed25519 for use w/ EdDSA only",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "OKP-Ed448": {
    "Name": "Ed448",
    "Value": "7",
    "Key Type": "OKP",
    "Description": "Ed448 for use w/ EdDSA only",
    "Change Controller": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053",
    "Recommended": "Yes"
  },
  "EC2-secp256k1": {
    "Name": "secp256k1",
    "Value": "8",
    "Key Type": "EC2",
    "Description": "SECG secp256k1 curve",
    "Change Controller": "IESG",
    "Reference": "https://datatracker.ietf.org/doc/RFC8812",
    "Recommended": "No"
  },
  "9-255": {
    "Name": "Unassigned",
    "Value": "9-255",
    "Key Type": "",
    "Description": "",
    "Change Controller": "",
    "Reference": "",
    "Recommended": ""
  },
  "EC2-brainpoolP256r1": {
    "Name": "brainpoolP256r1",
    "Value": "256",
    "Key Type": "EC2",
    "Description": "BrainpoolP256r1",
    "Change Controller": "[ISO/IEC JTC 1/SC 17/WG 10]",
    "Reference": "[ISO/IEC 18013-5:2021, 9.1.5.2]",
    "Recommended": "No"
  },
  "EC2-brainpoolP320r1": {
    "Name": "brainpoolP320r1",
    "Value": "257",
    "Key Type": "EC2",
    "Description": "BrainpoolP320r1",
    "Change Controller": "[ISO/IEC JTC 1/SC 17/WG 10]",
    "Reference": "[ISO/IEC 18013-5:2021, 9.1.5.2]",
    "Recommended": "No"
  },
  "EC2-brainpoolP384r1": {
    "Name": "brainpoolP384r1",
    "Value": "258",
    "Key Type": "EC2",
    "Description": "BrainpoolP384r1",
    "Change Controller": "[ISO/IEC JTC 1/SC 17/WG 10]",
    "Reference": "[ISO/IEC 18013-5:2021, 9.1.5.2]",
    "Recommended": "No"
  },
  "EC2-brainpoolP512r1": {
    "Name": "brainpoolP512r1",
    "Value": "259",
    "Key Type": "EC2",
    "Description": "BrainpoolP512r1",
    "Change Controller": "[ISO/IEC JTC 1/SC 17/WG 10]",
    "Reference": "[ISO/IEC 18013-5:2021, 9.1.5.2]",
    "Recommended": "No"
  }
};