
const AlgToTags: any = {
  ES256: -7,
  ES384: -35,
  ES512: -36,
};

const Translators: any = {
  kid: (value: any) => {
    return Buffer.from(value, 'utf8');
  },
  alg: (value: any) => {
    if (!(AlgToTags[value])) {
      throw new Error('Unknown \'alg\' parameter, ' + value);
    }
    return AlgToTags[value];
  }
};

const HeaderParameters: any = {
  partyUNonce: -22,
  static_key_id: -3,
  static_key: -2,
  ephemeral_key: -1,
  alg: 1,
  crit: 2,
  content_type: 3,
  ctyp: 3, // one could question this but it makes testing easier
  kid: 4,
  IV: 5,
  Partial_IV: 6,
  counter_signature: 7,
  x5chain: 33
};

export const EMPTY_BUFFER = Buffer.alloc(0);

export const TranslateHeaders = function (header: any) {
  const result = new Map();
  for (const param in header) {
    if (!HeaderParameters[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = header[param];
    if (Translators[param]) {
      value = Translators[param](header[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(HeaderParameters[param], value);
    }
  }
  return result;
};

const KeyParameters: any = {
  crv: -1,
  k: -1,
  x: -2,
  y: -3,
  d: -4,
  kty: 1
};

const KeyTypes: any = {
  OKP: 1,
  EC2: 2,
  RSA: 3,
  Symmetric: 4
};

const KeyCrv: any = {
  'P-256': 1,
  'P-384': 2,
  'P-521': 3,
  X25519: 4,
  X448: 5,
  Ed25519: 6,
  Ed448: 7
};

const KeyTranslators: any = {
  kty: (value: any) => {
    if (!(KeyTypes[value])) {
      throw new Error('Unknown \'kty\' parameter, ' + value);
    }
    return KeyTypes[value];
  },
  crv: (value: any) => {
    if (!(KeyCrv[value])) {
      throw new Error('Unknown \'crv\' parameter, ' + value);
    }
    return KeyCrv[value];
  }
};

export const TranslateKey = function (key: any) {
  const result = new Map();
  for (const param in key) {
    if (!KeyParameters[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = key[param];
    if (KeyTranslators[param]) {
      value = KeyTranslators[param](value);
    }
    result.set(KeyParameters[param], value);
  }
  return result;
};

export const xor = function (a: any, b: any) {
  const buffer = Buffer.alloc(Math.max(a.length, b.length));
  for (let i = 1; i <= buffer.length; ++i) {
    const av = (a.length - i) < 0 ? 0 : a[a.length - i];
    const bv = (b.length - i) < 0 ? 0 : b[b.length - i];
    buffer[buffer.length - i] = av ^ bv;
  }
  return buffer;
};

export { HeaderParameters }

export const runningInNode = function () {
  return Object.prototype.toString.call(global.process) === '[object process]';
};
