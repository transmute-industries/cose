
import { IANACOSEAlgorithms } from '../algorithms';

const algorithms = Object.values(IANACOSEAlgorithms)

const getAlgFromVerificationKey = (alg: string): number => {
  const foundAlg = algorithms.find((entry) => {
    return entry.Name === alg
  })
  if (alg === 'ML-DSA-65') {
    return -49
  }
  if (!foundAlg) {
    throw new Error('This library requires keys to contain fully specified algorithms')
  }
  return parseInt(foundAlg.Value, 10)
}

export default getAlgFromVerificationKey