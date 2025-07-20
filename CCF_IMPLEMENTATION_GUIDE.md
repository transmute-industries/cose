# CCF Receipt Verification Implementation Guide

## 🎯 **Overview**

This library provides **production-ready CCF (Confidential Consortium Framework) receipt verification** that works with real CCF ledger receipts following the draft-birkholz-cose-receipts-ccf-profile specification.

**Status:** ✅ **Production Ready** - Successfully verifies real CCF receipts

---

## 📋 **Implementation**

### **Core Files:**
- `src/drafts/draft-birkholz-cose-receipts-ccf-profile/ccf_verifier.ts` - Main implementation
- `tests/scitt-statements/scitt-statement-verification.test.ts` - Integration tests

### **Key Functions:**
1. `verifyCCFInclusionReceipt()` - Main entry point for CCF receipt verification
2. `verifyCCFReceiptCore()` - Core verification algorithm
3. `createCCFInclusionReceipt()` - Receipt creation utility

---

## 🔧 **Technical Implementation**

### **CCF Verification Algorithm**

The implementation follows the CCF standard approach:

#### **1. COSE Sign1 Structure**
CCF receipts use standard COSE Sign1 signatures with the computed Merkle tree root as the payload.

#### **2. Merkle Tree Computation**
```typescript
// Compute leaf hash: sha256(leaf[0] + sha256(leaf[1]) + leaf[2])
const leafMiddleHash = hashFunction(new TextEncoder().encode(leaf[1]))
const leafHash = hashFunction(new Uint8Array([...leaf[0], ...leafMiddleHash, ...leaf[2]]))
let accumulator = leafHash

// Follow path to compute root
for (const [left, digest] of path) {
    if (left) {
        accumulator = hashFunction(new Uint8Array([...digest, ...accumulator]))
    } else {
        accumulator = hashFunction(new Uint8Array([...accumulator, ...digest]))
    }
}
```

#### **3. CBOR Map Proof Structure**
- **Leaf Label (1)**: `[internal_hash, internal_data, claim_digest]`
- **Path Label (2)**: `[[left_bool, hash], ...]`

### **Main API**

#### **Receipt Verification**
```typescript
export async function verifyCCFInclusionReceipt(
    inclusionReceipt: Uint8Array,
    hashFunction: (data: Uint8Array) => Uint8Array,
    verifier?: any,
    signedStatement?: Uint8Array
): Promise<boolean>
```

#### **Core Implementation**
```typescript
export async function verifyCCFReceiptCore(
    inclusionReceipt: Uint8Array,
    hashFunction: (data: Uint8Array) => Uint8Array,
    verifier: any,
    claimDigest: Uint8Array
): Promise<boolean>
```

**Implementation Details:**
1. **CBOR Map Handling**: Properly extracts leaf and path from CBOR Map structure
2. **Merkle Tree Computation**: Follows CCF specification for root calculation
3. **COSE Verification**: Uses computed root as detached signature payload
4. **Claim Verification**: Validates claim digest matches leaf data

---

## 🧪 **Verification Results**

### **Successful CCF Receipt Verification:**

```
🚀 Using CCF verification
✅ CCF verification: SUCCESS
✅ Claim digest matches leaf data  
✅ CCF receipt verified (signature + proof)
```

### **Verified Components:**
- **Merkle Tree**: Multi-step path computation with correct root calculation
- **COSE Signature**: ES384 signature verification with CCF public keys
- **Proof Structure**: CBOR Map with proper leaf/path extraction
- **Claim Matching**: Hash verification against leaf data

---

## 📝 **Usage Example**

```typescript
import * as cose from '@transmute/cose'

// Verify CCF receipt
const verified = await cose.verifyCCFInclusionReceipt(
    ccfReceipt,              // CCF receipt bytes
    sha256HashFunction,      // Hash function (SHA-256)
    coseVerifier,           // COSE verifier with CCF public key
    signedStatement         // Original signed statement
)

console.log(`CCF Receipt Verified: ${verified}`)
```

---

## 🔍 **CCF Profile Requirements**

### **Protected Header Requirements:**
- **Algorithm**: ES256, ES384, or ES512 
- **Key ID**: CCF service key identifier
- **VDS**: Verifiable Data Structure = 2 (CCF)
- **CWT Claims**: Issuer and subject information

### **Unprotected Header Requirements:**
- **Verifiable Data Proofs**: CBOR Map containing inclusion proofs
- **Proof Label -1**: Array of inclusion proof data

### **Proof Structure:**
- **CBOR Map format** with labels 1 (leaf) and 2 (path)
- **Leaf**: 3-element array `[internal_hash, internal_data, claim_digest]`
- **Path**: Array of `[left_bool, sibling_hash]` pairs

---

## 🚀 **Implementation Features**

### **Production Ready:**
- ✅ **Real CCF receipt verification** in TypeScript
- ✅ **Complete interoperability** with CCF ledger services
- ✅ **Enterprise-grade reliability** for production applications

### **Clean Architecture:**
- **Focused Implementation**: Single CCF verification path
- **Production-Optimized**: Streamlined for real-world usage
- **Standard Compliant**: Follows draft-birkholz-cose-receipts-ccf-profile

### **Comprehensive Testing:**
- Integration tests with real CCF receipts
- Unit tests for all verification components  
- Error handling for malformed receipts
- Edge case validation

---

## 📚 **References**

### **Specifications:**
- [COSE Merkle Tree Proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- [COSE Receipts CCF Profile](https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/)
- [COSE (RFC 8152)](https://tools.ietf.org/html/rfc8152)

### **CCF Framework:**
- [Confidential Consortium Framework](https://www.microsoft.com/en-us/research/project/confidential-consortium-framework/)

---

## 🏆 **Summary**

This implementation provides **complete CCF receipt verification** capability for TypeScript applications. The implementation follows the CCF specification for computing Merkle tree roots and uses standard COSE Sign1 verification with the computed root as the payload.

**Key Benefits:**
- **Interoperability**: Works with real CCF ledger receipts
- **Standards Compliant**: Follows CCF profile specification  
- **Production Ready**: Enterprise-grade verification reliability
- **Simple API**: Easy integration into existing applications 