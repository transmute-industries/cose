import * as sign1 from "../sign1"

export const signer = ({ remote }: sign1.RequestCoseSign1Signer) => {
  const coseSign1Signer = sign1.signer({ remote })
  return {
    sign: (req: sign1.RequestCoseSign1) => {
      return coseSign1Signer.sign(req)
    }
  }
}

export const verifier = ({ resolver }: sign1.RequestCoseSign1Verifier) => {
  return {
    verify: async (req: sign1.RequestCoseSign1Verify) => {
      const coseSign1Verifier = sign1.verifier({ resolver })
      return coseSign1Verifier.verify(req)
    }
  }
}