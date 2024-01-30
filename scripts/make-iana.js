
const axios = require('axios');
const csv = require('csv-parser');

const csvUrlToMap = async (url) => {
  const response = await axios.get(url, {
    // headers: {Authorization: `Bearer ${token}`, 
    responseType: 'stream'
  });
  return new Promise((resolve, reject) => {

    const stream = response.data.pipe(csv());
    const map = {}
    stream.on('data', row => {
      if (row.Reference.startsWith('[RFC')) {
        row.Reference = `https://datatracker.ietf.org/doc/${row.Reference.substring(1, row.Reference.length - 1)}`
      }
      map[row.Value] = row
    });
    stream.on('end', () => {
      resolve(map)
    });
  })
}


module.exports = { csvUrlToMap }
