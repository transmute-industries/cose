
const axios = require('axios');
const fs = require('fs');
const csv = require('csv-parser');

const iana = 'https://www.iana.org/assignments/cose/header-parameters.csv';

(async () => {
  const response = await axios.get(iana, {
    // headers: {Authorization: `Bearer ${token}`, 
    responseType: 'stream'
  });
  const stream = response.data.pipe(csv());
  const IANACOSEHeaders = {}
  stream.on('data', row => {
    if (row.Reference.startsWith('[RFC')) {
      row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
    }
    IANACOSEHeaders[row.Label] = row
  });
  stream.on('end', () => {
    const file = `

export type IANACOSEHeader = {
  Name: string
  Label: string
  'Value Type': string
  'Value Registry': string
  Description: string
  Reference: string
}

export const IANACOSEHeaders: Record<string, IANACOSEHeader> = ${JSON.stringify(IANACOSEHeaders, null, 2)};
            `
    fs.writeFileSync('./src/cose/headers.ts', file.trim())
  });
})()