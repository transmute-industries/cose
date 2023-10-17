export const Sign1Tag = 18;

export const EMPTY_BUFFER = Buffer.alloc(0);

export const HeaderParameters: any = {
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