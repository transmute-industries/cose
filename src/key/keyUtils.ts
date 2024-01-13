
import { publicFromPrivate } from "./publicFromPrivate";

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms

const reverse = (map: Map<any, any>) => new Map(Array.from(map, (a: any) => a.reverse()))

const algsMap = new Map([
  [-7, 'ES256'],
  [-35, 'ES384'],
  [-36, 'ES512'],
  [35, 'HPKE-Base-P256-SHA256-AES128GCM']
]);

const algorithms = {
  toJOSE: algsMap,
  toCOSE: reverse(algsMap)
}

const paramsMap = new Map([
  [1, 'kty'],
  [2, 'kid'],
  [3, 'alg'],
  [-1, 'crv'],
  [-2, 'x'],
  [-3, 'y'],
  [-4, 'd'],
  // Reserved for Private Use: less than -65536
  [-66666, 'x5c'],
  [-66667, `x5t#S256`]
]);

const parameters = {
  toJOSE: paramsMap,
  toCOSE: reverse(paramsMap)
}

const curvesMap = new Map([
  [1, 'P-256'],
  [2, 'P-384'],
  [3, 'P-521'],
]);

const curves = {
  toJOSE: curvesMap,
  toCOSE: reverse(curvesMap)
}

const typesMap = new Map([
  [2, 'EC'],
]);

const types = {
  toJOSE: typesMap,
  toCOSE: reverse(typesMap)
}


export const keyUtils = {
  publicFromPrivate,
  algorithms,
  parameters,
  curves,
  types
}

export default keyUtils