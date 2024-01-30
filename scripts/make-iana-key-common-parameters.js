


const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/key-common-parameters.csv')
  const file = `
export type IANACOSEKeyCommonParameter = {
  Name: string
  Label: string
  'CBOR Type': string
  'Value Registry': string
  Description: string
  Reference: string
}
export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = ${JSON.stringify(record, null, 2)};
`
  fs.writeFileSync('./src/cose/key-common-parameters.ts', file.trim())
})()