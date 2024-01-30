




const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/key-type.csv')
  const file = `
export type IANACOSEKeyType = {
  Name: string
  Value: string
  Description: string
  Capabilities: string
  Reference: string
}
export const IANACOSEKeyTypes: Record<string, IANACOSEKeyType> = ${JSON.stringify(record, null, 2)};
`
  fs.writeFileSync('./src/cose/key-type.ts', file.trim())
})()