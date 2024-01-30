

const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/key-type-parameters.csv')
  const file = `
export type IANACOSEKeyCommonParameter = {
  'Key Type': string
  'Name': string
  'Label': string
  'CBOR Type': string
  Description: string
  Reference: string
}
export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = ${JSON.stringify(record, null, 2)};
            `
  fs.writeFileSync('./src/cose/key-type-parameters.ts', file.trim())
})()