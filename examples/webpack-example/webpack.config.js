
const path = require('path');
module.exports = [{
  mode: 'development',
  entry: './index.js',
  watch: true,
  plugins: [],
  resolve: {
    alias: {
      'hpke-js': path.resolve('./node_modules/hpke-js')
    },
    fallback: {
      "crypto": false
    }
  }
}];
