
const fs = require('fs');
const cose = require('@transmute/cose').default;

(async () => {
  // const publicKey = fs.readFileSync('publicKey.cose');
  // const publicKeyMap = cose.cbor.decode(publicKey)
  // const publicKeyDiagnostic = cose.key.edn(publicKeyMap)
  // console.log(publicKeyDiagnostic)

  // const secretKey = fs.readFileSync('secretKey.cose');
  // const secretKeyMap = cose.cbor.decode(secretKey)
  // const secretKeyDiagnostic = cose.key.edn(secretKeyMap)
  // console.log(secretKeyDiagnostic)

  // const sign1 = fs.readFileSync('sign1.cose');
  // const diags = await cose.rfc.diag(new Uint8Array(sign1))
  // console.log(cose.rfc.blocks(diags))


  const publicKey2 = fs.readFileSync('dilithium.publicKey.cose');
  const publicKeyMap2 = cose.cbor.decode(publicKey2)
  const publicKeyDiagnostic2 = cose.key.edn(publicKeyMap2)
  console.log(publicKeyDiagnostic2)


  const sign12 = fs.readFileSync('dilithium.sign1.cose');
  const diags2 = await cose.rfc.diag(new Uint8Array(sign12))
  console.log(cose.rfc.blocks(diags2))


  // const secretKey2 = fs.readFileSync('dilithium.secretKey.cose');
  // const secretKeyMap2 = cose.cbor.decode(secretKey2)
  // const secretKeyDiagnostic2 = cose.key.edn(secretKeyMap2)
  // console.log(secretKeyDiagnostic2)
})()