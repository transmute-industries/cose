


const fs = require('fs');
const { csvUrlToMap } = require('./make-iana');

(async () => {
  const record = await csvUrlToMap('https://www.iana.org/assignments/cose/elliptic-curves.csv')
  const file = `


export type IANACOSEEllipticCurve = {
  Name: string
  Value: string
  'Key Type': string
  Description: string
  'Change Controller': string
  Reference: string
  Recommended: string
}
export const IANACOSEEllipticCurves: Record<string, IANACOSEEllipticCurve> = ${JSON.stringify(record, null, 2)};
`
  fs.writeFileSync('./src/cose/elliptic-curves.ts', file.trim())
})()