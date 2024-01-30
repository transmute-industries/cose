





const axios = require('axios');
const fs = require('fs');
const csv = require('csv-parser');

const iana = 'https://www.iana.org/assignments/cose/key-type-parameters.csv';

(async () => {
  const response = await axios.get(iana, {
    // headers: {Authorization: `Bearer ${token}`, 
    responseType: 'stream'
  });
  const stream = response.data.pipe(csv());
  const IANACOSEKeyTypeParameters = {}
  stream.on('data', row => {
    if (row.Reference.startsWith('[RFC')) {
      row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
    }
    IANACOSEKeyTypeParameters[row.Label] = row
  });
  stream.on('end', () => {
    const file = `

export type IANACOSEKeyCommonParameter = {
  'Key Type': string
  'Name': string
  'Label': string
  'CBOR Type': string
  Description: string
  Reference: string
}

export const IANACOSEKeyCommonParameters: Record<string, IANACOSEKeyCommonParameter> = ${JSON.stringify(IANACOSEKeyTypeParameters, null, 2)};
            `
    fs.writeFileSync('./src/cose/key-type-parameters.ts', file.trim())
  });
})()