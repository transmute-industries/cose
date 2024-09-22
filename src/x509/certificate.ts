import { exportJWK, exportPKCS8, importPKCS8 } from 'jose';

import * as x509 from "@peculiar/x509";

import { detached } from '..';
import { crypto } from '..';
import { JWK } from 'jose'
import * as cose from '../iana/assignments/cose';
import { labels_to_algorithms } from '../iana/requested/cose';

import { web_key_type } from '../iana/assignments/jose';

import { RequestCoseSign1DectachedVerify } from '../../src/cose/sign1/types';


// eslint-disable-next-line @typescript-eslint/no-empty-function
const nodeCrypto = import('crypto').catch(() => { })

const extractable = true;

const provide = async () => {
  try {
    return window.crypto
  } catch (e) {
    return (await (await nodeCrypto) as Crypto)
  }
}

// need to DRY...
const algTowebCryptoParams: Record<string, { name: string, hash: string, namedCurve: string }>
  = {
  'ESP256': {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  },
  'ESP384': {
    name: "ECDSA",
    hash: "SHA-384",
    namedCurve: "P-384",
  },
  'ES256': {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  },
  'ES384': {
    name: "ECDSA",
    hash: "SHA-384",
    namedCurve: "P-384",
  },
  'ES512': {
    name: "ECDSA",
    hash: "SHA-512",
    namedCurve: "P-521",
  }
}

export type RequestRootCertificate = {
  alg: string
  sub: string
  iss: string
  nbf: string
  exp: string
  serial: string
}

// https://datatracker.ietf.org/doc/html/rfc9360#section-2-5.6.1
const thumbprint = async (cert: string): Promise<[number, ArrayBuffer]> => {
  const current = new x509.X509Certificate(cert)
  return [cose.algorithm.sha_256, await current.getThumbprint('SHA-256')]
}

export type RootCertificateResponse = { public: string, private: string }

const root = async (req: RequestRootCertificate): Promise<RootCertificateResponse> => {
  const crypto = await provide()
  x509.cryptoProvider.set(crypto);
  const extensions: x509.JsonGeneralNames = [
    // {
    //   type: 'url', value: `https://vendor.example`
    // }
  ]
  const webCryptoAlgorithm = algTowebCryptoParams[req.alg]
  const caKeys = await crypto.subtle.generateKey(webCryptoAlgorithm, extractable, ["sign", "verify"]);
  const caCert = await x509.X509CertificateGenerator.create({
    serialNumber: req.serial || "01",
    subject: req.sub,
    issuer: req.iss,
    notBefore: new Date(req.nbf),
    notAfter: new Date(req.exp),
    signingAlgorithm: webCryptoAlgorithm,
    publicKey: caKeys.publicKey,   // self signed
    signingKey: caKeys.privateKey, // self signed
    extensions: [
      new x509.SubjectAlternativeNameExtension(extensions),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)
    ]
  });
  const certPublic = caCert.toString()
  const certPrivate = await exportPKCS8(caKeys.privateKey)
  return { public: certPublic, private: certPrivate };
}


const pkcs8Signer = async ({ alg, privateKeyPKCS8 }: { alg: number, privateKeyPKCS8: string }) => {
  const algName = labels_to_algorithms.get(alg)
  const privateKeyJwk = await exportJWK(await importPKCS8(privateKeyPKCS8, `${algName}`)) as JWK
  privateKeyJwk.alg = algName;
  return detached.signer({
    remote: crypto.signer({
      privateKeyJwk
    })
  })
}

export type RequestCertificateVerifier = {
  resolver: {
    resolve: (signature: ArrayBuffer) => Promise<web_key_type>
  }
}


const verifier = ({ resolver }: RequestCertificateVerifier) => {
  return {
    verify: async (req: RequestCoseSign1DectachedVerify) => {
      const verifier = detached.verifier({ resolver })
      return verifier.verify(req)
    }
  }
}

export const certificate = { thumbprint, root, pkcs8Signer, verifier }