import { Buffer } from "safe-buffer"
// @ts-ignore
import jwa from "jwa"
import toString from "./tostring"

function base64url(str: string, encoding?: string) {
  return Buffer.from(str, encoding)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
}

function jwsSecuredInput(
  header: object,
  payload: object,
  encoding: string = "utf8",
) {
  const encodedHeader = base64url(toString(header), "binary")
  const encodedPayload = base64url(toString(payload), encoding)
  return `${encodedHeader}.${encodedPayload}`
}

type Options = {
  header: { alg: string }
  payload: object
  secret?: string
  privateKey?: string
  encoding?: string
}

export function sign(opts: Options) {
  const { header, payload, encoding = "utf8", secret, privateKey } = opts
  const secretOrKey = secret || privateKey

  const algo = jwa(header.alg)
  const securedInput = jwsSecuredInput(header, payload, encoding)
  const signature = algo.sign(securedInput, secretOrKey)
  return `${securedInput}.${signature}`
}
