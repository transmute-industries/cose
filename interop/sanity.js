
const fs = require('fs');
const cose = require('@transmute/cose').default;

(async ()=> {
  const publicKey = fs.readFileSync('publicKey.cose');
  const publicKeyMap = cose.cbor.decode(publicKey)
  const publicKeyDiagnostic = cose.key.edn(publicKeyMap)
  console.log(publicKeyDiagnostic)

  const secretKey = fs.readFileSync('secretKey.cose');
  const secretKeyMap = cose.cbor.decode(secretKey)
  const secretKeyDiagnostic = cose.key.edn(secretKeyMap)
  console.log(secretKeyDiagnostic)
})()