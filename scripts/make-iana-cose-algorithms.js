
const axios = require('axios');
const fs = require('fs');
const csv = require('csv-parser');

const iana = 'https://www.iana.org/assignments/cose/algorithms.csv';

(async () => {
  const response = await axios.get(iana, {
    // headers: {Authorization: `Bearer ${token}`, 
    responseType: 'stream'
  });
  const stream = response.data.pipe(csv());
  const IANACOSEAlgorithms = {}
  stream.on('data', row => {
    if (row.Reference.startsWith('[RFC')) {
      row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
    }
    IANACOSEAlgorithms[row.Value] = row
  });
  stream.on('end', () => {
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
export const IANACOSEHeaderParameters: Record<string, IANACOSEAlgorithm> = ${JSON.stringify(IANACOSEAlgorithms, null, 2)};
            `
    fs.writeFileSync('./src/cose/alg.ts', file.trim())
  });
})()