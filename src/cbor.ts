import * as web from 'cbor-web'
const cbor = {
  web,
  encode: (data: string | number | object) => {
    const buf = web.encode(data)
    return new Uint8Array(buf)
  },
  decode: (data: Uint8Array) => {
    return web.decode(data)
  },
}
export default cbor
