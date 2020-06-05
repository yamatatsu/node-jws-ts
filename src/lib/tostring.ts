import { Buffer } from "safe-buffer"

export default function toString(obj: any) {
  if (typeof obj === "string") return obj

  if (typeof obj === "number" || Buffer.isBuffer(obj)) return obj.toString()

  return JSON.stringify(obj)
}
