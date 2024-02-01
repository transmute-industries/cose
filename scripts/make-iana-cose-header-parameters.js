const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/header-parameters.csv')
  const file = `
  export type IANACOSEHeaderParameter = {
    Name: string
    Label: string
    'Value Type': string
    'Value Registry': string
    Description: string
    Reference: string
  }
  export const IANACOSEHeaderParameters: Record<string, IANACOSEHeaderParameter> = ${JSON.stringify(record, null, 2)};
              `
  fs.writeFileSync('./src/cose/header-parameters.ts', file.trim())
})()