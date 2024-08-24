

import { IANACOSEAlgorithms, IANACOSEAlgorithm } from '../cose/algorithms';

const algorithms = Object.values(IANACOSEAlgorithms)

const ESP256 = {
  Name: 'ESP256',
  Value: '-9'
} as IANACOSEAlgorithm

const ESP384 = {
  Name: 'ESP384',
  Value: '-48'
} as IANACOSEAlgorithm

const fullySpecifiedByName = {
  ESP256,
  ESP384
} as Record<string, IANACOSEAlgorithm>

const fullySpecifiedByLabel = {
  [ESP256.Value]: ESP256,
  [ESP384.Value]: ESP384,
} as Record<string, IANACOSEAlgorithm>

export const iana = {
  'COSE Algorithms': {
    'less-specified': (alg: string) => {
      if (alg === 'ESP256') {
        return 'ES256'
      }
      if (alg === 'ESP384') {
        return 'ES384'
      }
      return alg
    },
    getByName: (name: string) => {
      const foundAlgorithm = algorithms.find((param) => {
        return param.Name === name
      })
      if (foundAlgorithm && foundAlgorithm.Name !== 'Unassigned') {
        return foundAlgorithm
      }
      // extensions
      if (fullySpecifiedByName[name]) {
        return fullySpecifiedByName[name]
      }
    },
    getByValue: (value: number) => {
      const foundAlgorithm = algorithms.find((param) => {
        return param.Value === `${value}`
      })
      if (foundAlgorithm && foundAlgorithm.Name !== 'Unassigned') {
        return foundAlgorithm
      }
      // extensions
      if (fullySpecifiedByLabel[`${value}`]) {
        return fullySpecifiedByLabel[`${value}`]
      }
    }
  }
}

