export type AlgorithmSummary = {
  alg: string
  digest: string
  crv: string
}
export const AlgFromTags: Record<number, AlgorithmSummary> = {};
AlgFromTags[-7] = { alg: 'ES256', digest: 'SHA-256', crv: 'P-256' };
AlgFromTags[-35] = { alg: 'ES384', digest: 'SHA-384', crv: 'P-384' };
AlgFromTags[-36] = { alg: 'ES512', digest: 'SHA-512', crv: 'P-521' };
