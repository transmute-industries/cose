export type UnprotectedHeaderMap = Map<string | number, any>
export type ProtectedHeaderMap = Map<string | number, any>

export const HeaderParameters = {
  alg: 1,
  crit: 2,
  content_type: 3,
  kid: 4,
  counter_signature: 7
};