
import * as transmute from '@transmute/cose'

const test = () => {
  console.log(transmute);
  console.log('test complete.');
}
// setup exports on window
window.test = {
  test
}
