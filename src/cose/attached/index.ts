import * as sign1 from "../sign1"

export const signer = ({ secretKeyJwk }: sign1.RequestCoseSign1Signer) => {
  const signer = sign1.signer({ secretKeyJwk })
  return {
    sign: (req: sign1.RequestCoseSign1) => {
      return signer.sign(req)
    }
  }
}

export const verifier = ({ publicKeyJwk }: sign1.RequestCoseSign1Verifier) => {
  const verifier = sign1.verifier({ publicKeyJwk })
  return {
    verify: (req: sign1.RequestCoseSign1Verify) => {
      return verifier.verify(req)
    }
  }
}