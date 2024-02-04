import * as sign1 from "../sign1"

export const signer = ({ rawSigner }: sign1.RequestCoseSign1Signer) => {
  const coseSign1Signer = sign1.signer({ rawSigner })
  return {
    sign: (req: sign1.RequestCoseSign1) => {
      return coseSign1Signer.sign(req)
    }
  }
}

export const verifier = ({ publicKeyJwk }: sign1.RequestCoseSign1Verifier) => {
  const coseSign1Verifier = sign1.verifier({ publicKeyJwk })
  return {
    verify: (req: sign1.RequestCoseSign1Verify) => {
      return coseSign1Verifier.verify(req)
    }
  }
}