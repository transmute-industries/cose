
import transmute from '../src'

it("binary diagnostic sanity", async () => {
  const message = `💣✨🔥`
  const message1 = new TextEncoder().encode(message)
  const message2 = transmute.utils.typedArrayToBuffer(message1)
  const message3 = Buffer.from(message)
  expect(await transmute.cbor.web.diagnose(transmute.cbor.web.encode(message))).toBe(`"💣✨🔥"\n`)
  expect(await transmute.cbor.web.diagnose(transmute.cbor.web.encode(message1))).toBe(`64(h'f09f92a3e29ca8f09f94a5')\n`)
  expect(await transmute.cbor.web.diagnose(transmute.cbor.web.encode(message2))).toBe(`h'f09f92a3e29ca8f09f94a5'\n`)
  expect(await transmute.cbor.web.diagnose(transmute.cbor.web.encode(message3))).toBe(`h'f09f92a3e29ca8f09f94a5'\n`)
})