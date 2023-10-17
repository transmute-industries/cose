export type UnprotectedHeaderMap = Map<string | number, any>
export type ProtectedHeaderMap = Map<string | number, any>


export type ProtectedHeaderLabels = 'alg' | 'crit' | 'content_type' | 'kid' | 'counter_signature'
export type ProtectedHeaderTags = 1 | 2 | 3 | 4 | 7

export const labelToTag = new Map<ProtectedHeaderLabels, ProtectedHeaderTags>()
labelToTag.set('alg', 1)
labelToTag.set('crit', 2)
labelToTag.set('content_type', 3)
labelToTag.set('kid', 4)
labelToTag.set('counter_signature', 7)

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const tagToLabel = new Map(Array.from(labelToTag, (a: any) => a.reverse()))


export function getCommonParameter(protectedHeaderMap: ProtectedHeaderMap, unprotectedHeaderMap: UnprotectedHeaderMap, tag: number | undefined): number {
  if (tag === undefined) {
    throw new Error('Cannot get parameter from undefined tag')
  }
  let result;
  if (protectedHeaderMap.get) {
    result = protectedHeaderMap.get(tag);
  }
  if (!result && unprotectedHeaderMap.get) {
    result = unprotectedHeaderMap.get(tag);
  }
  if (!result) {
    throw new Error(`Could not get header parameter by label: ${tag}`)
  }
  return result
}
