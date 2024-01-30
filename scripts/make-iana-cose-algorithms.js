const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/algorithms.csv')
  const file = `
  export type IANACOSEAlgorithm = {
    Name: string
    Value: string
    Description: string
    Capabilities: string
    'Change Controller': string
    Recommended: string
    Reference: string
  }
  export const IANACOSEAlgorithms: Record<string, IANACOSEAlgorithm> = ${JSON.stringify(record, null, 2)};
              `
  fs.writeFileSync('./src/cose/algorithms.ts', file.trim())
})()