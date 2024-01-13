// import fs from 'fs'
// import generate from '../jose/generate'
// import wrap from './wrap'
// import * as coseKey from '../../../src/key'
// import { Suite0 } from '../common'
// import alternateDiagnostic from '../../../src/diagnostic'
// import cbor from '../../../src/cbor'

import cbor from "../../../../src/cbor"

import wrap from '../wrap'

it('send 2 layer to friend', async () => {
  // {
  //     / kty = 'EC2' /
  //     1: 2,
  //     / kid = '01' /
  //     2: h'3031',
  //     / alg = HPKE-Base-P256-SHA256-AES128GCM (Assumed: 35) /
  //     3: 35,
  //     / crv = 'P-256' /
  //     -1: 1,
  //     / x /
  //     -2: h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d',
  //     / y /
  //     -3: h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'
  // }
  const recipientPublicKey = new Map<number, number | Buffer>([
    [1, 2], // kty = 'EC2' /
    [2, Buffer.from('3031', 'hex')], // kid = '01' /
    [3, 35], // alg = HPKE-Base-P256-SHA256-AES128GCM (Assumed: 35) /
    [-1, 1], // crv = 'P-256' /
    [-2, Buffer.from('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', 'hex')], // x /
    [-3, Buffer.from('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', 'hex')], // y /
  ])
  const pt = 'hello world'
  const m = new TextEncoder().encode(pt)
  const c4 = await wrap.encrypt(m, recipientPublicKey)
  // console.log(c4.toString('hex'))
  // d8608443a10101a1054cc76efc0f1b057e5776bd70d0581b86ca9fcb76c70878e21a3a060b5783e9aed4be2826f95b9cacd766818344a1011823a20442303123584104cd5924f279ef1cd99ba24243cec2b5f795058e657f973d873ea99fa8a020d31b980644528636ec1cb1011e9b0828d4598054004188bd28b64da3bab0eb2fcc5c5820114637018aaac9cf03c81db3fa9c5fa15ef4b0d140edd4da815eada6e053fd9e
  const diagnostic = await cbor.diagnose(c4)
  // console.log(diagnostic)
  // 96([
  //   h'a10101', 
  //   {
  //     5: h'c76efc0f1b057e5776bd70d0'
  //   }, 
  //   h'86ca9fcb76c70878e21a3a060b5783e9aed4be2826f95b9cacd766', 
  //   [
  //     [
  //       h'a1011823', 
  //       {
  //         4: h'3031',
  //         -4: h'04cd5924f279ef1cd99ba24243cec2b5f795058e657f973d873ea99fa8a020d31b980644528636ec1cb1011e9b0828d4598054004188bd28b64da3bab0eb2fcc5c'
  //       }, 
  //       h'114637018aaac9cf03c81db3fa9c5fa15ef4b0d140edd4da815eada6e053fd9e'
  //     ]
  //   ]
  // ])
})