
const fs = require('fs');
const jose = require('jose')
const makePrettyKey = (jwk) => {
  const prettyKey = {}
  for (const [key, value] of Object.entries(jwk)) {
    if (value.length < 32) {
      prettyKey[key] = value
    } else {
      prettyKey[key] = value.substring(0, 8) + '...' + value.substring(value.length - 8, value.length)
    }
  }
  return prettyKey
}


const makeDilithiumReadme = async () => {
  const publicKey = JSON.parse(fs.readFileSync('dilithium.publicKey.jwk.json').toString());
  const prettyPublicKey = makePrettyKey(publicKey)

  const secretKey = JSON.parse(fs.readFileSync('dilithium.secretKey.jwk.json').toString());
  const prettySecretKey = makePrettyKey(secretKey)


  const jws = fs.readFileSync('dilithium.jws.jose').toString()
  const [h, p] = jws.split('.')
  const header = JSON.parse(Buffer.from(h, 'base64').toString())
  const payload = JSON.parse(Buffer.from(p, 'base64').toString())






  const doc = `
# Proposal

[Read the draft](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)

"alg": "CRYDI2" ✨ new
"kty": "MLWE"   ✨ new

## Current

## Public Key
${JSON.stringify(prettyPublicKey, null, 2)}

## Private Key
${JSON.stringify(prettySecretKey, null, 2)}

## Protected Header 
\`\`\`json 
${JSON.stringify(header, null, 2)}
\`\`\`

## Protected Payload
\`\`\`json 
${JSON.stringify(payload, null, 2)}
\`\`\`

## JWS
\`\`\`text 
${jws}
\`\`\`
  `

  fs.writeFileSync('jose.README.md', doc)
}

(async () => {
  await makeDilithiumReadme()
})()


