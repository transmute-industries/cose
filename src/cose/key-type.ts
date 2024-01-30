export type IANACOSEKeyType = {
  Name: string
  Value: string
  Description: string
  Capabilities: string
  Reference: string
}
export const IANACOSEKeyTypes: Record<string, IANACOSEKeyType> = {
  "0": {
    "Name": "Reserved",
    "Value": "0",
    "Description": "This value is reserved",
    "Capabilities": "",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "1": {
    "Name": "OKP",
    "Value": "1",
    "Description": "Octet Key Pair",
    "Capabilities": "[kty(1), crv]",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "2": {
    "Name": "EC2",
    "Value": "2",
    "Description": "Elliptic Curve Keys w/ x- and y-coordinate pair",
    "Capabilities": "[kty(2), crv]",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "3": {
    "Name": "RSA",
    "Value": "3",
    "Description": "RSA Key",
    "Capabilities": "[kty(3)]",
    "Reference": "https://datatracker.ietf.org/doc/RFC8230][RFC9053"
  },
  "4": {
    "Name": "Symmetric",
    "Value": "4",
    "Description": "Symmetric Keys",
    "Capabilities": "[kty(4)]",
    "Reference": "https://datatracker.ietf.org/doc/RFC9053"
  },
  "5": {
    "Name": "HSS-LMS",
    "Value": "5",
    "Description": "Public key for HSS/LMS hash-based digital signature",
    "Capabilities": "[kty(5), hash algorithm]",
    "Reference": "https://datatracker.ietf.org/doc/RFC8778][RFC9053"
  },
  "6": {
    "Name": "WalnutDSA",
    "Value": "6",
    "Description": "WalnutDSA public key",
    "Capabilities": "[kty(6)]",
    "Reference": "https://datatracker.ietf.org/doc/RFC9021][RFC9053"
  }
};