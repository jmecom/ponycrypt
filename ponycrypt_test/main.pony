use "pony_test"
use "collections"
use pc = "ponycrypt"

actor Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  new make() =>
    None

  fun tag tests(test: PonyTest) =>
    test(_TestSha256KnownVectors)
    test(_TestHexDecode)
    test(_TestHmacSha256Rfc4231)
    test(_TestWycheproofHmacSha256)

class iso _TestSha256KnownVectors is UnitTest
  fun name(): String => "sha256/known-vectors"

  fun apply(h: TestHelper) =>
    h.assert_eq[String](
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      pc.Sha256.hex(""))
    h.assert_eq[String](
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      pc.Sha256.hex("abc"))
    h.assert_eq[String](
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      pc.Sha256.hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

class iso _TestHexDecode is UnitTest
  fun name(): String => "hex/decode"

  fun apply(h: TestHelper) ? =>
    h.assert_eq[String]("deadbeef", pc.Hex.encode(pc.Hex.decode("deadbeef")?))
    h.assert_error({()? => pc.Hex.decode("abc")? })
    h.assert_error({()? => pc.Hex.decode("zz")? })

class iso _TestHmacSha256Rfc4231 is UnitTest
  fun name(): String => "hmac-sha256/rfc4231"

  fun apply(h: TestHelper) ? =>
    let key1 = recover val
      let out = Array[U8](20)
      for i in Range[USize](0, 20) do out.push(0x0b) end
      out
    end
    let expected1 =
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    h.assert_eq[String](
      expected1,
      pc.Hex.encode(pc.Hmac[pc.Sha256].digest(key1, "Hi There")))
    h.assert_eq[String](
      expected1,
      pc.Hex.encode(pc.HmacSha256.digest(key1, "Hi There")))

    let expected2 =
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    h.assert_eq[String](
      expected2,
      pc.Hex.encode(pc.Hmac[pc.Sha256].digest("Jefe", "what do ya want for nothing?")))
    h.assert_eq[String](
      expected2,
      pc.Hex.encode(pc.Hmac[pc.Sha256].mac("Jefe", "what do ya want for nothing?")?))

    let key3 = recover val
      let out = Array[U8](20)
      for i in Range[USize](0, 20) do out.push(0xaa) end
      out
    end
    let data3 = recover val
      let out = Array[U8](50)
      for i in Range[USize](0, 50) do out.push(0xdd) end
      out
    end
    h.assert_eq[String](
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      pc.Hex.encode(pc.Hmac[pc.Sha256].digest(key3, data3)))

class iso _TestWycheproofHmacSha256 is UnitTest
  fun name(): String => "wycheproof/hmac-sha256"

  fun apply(h: TestHelper) ? =>
    var count: USize = 0
    for tc in WycheproofHmacSha256Vectors().values() do
      let key_iso = pc.Hex.decode(tc.key)?
      let key: Array[U8] val = consume key_iso
      let msg_iso = pc.Hex.decode(tc.msg)?
      let msg: Array[U8] val = consume msg_iso
      let expected_iso = pc.Hex.decode(tc.mac)?
      let expected: Array[U8] val = consume expected_iso

      let actual = pc.Hmac[pc.Sha256].mac(key, msg, tc.tag_size)?
      let actual_hex_iso = pc.Hex.encode(actual)
      let actual_hex: String val = consume actual_hex_iso
      let verify = pc.Hmac[pc.Sha256].verify(key, msg, expected)
      let label_iso = "tcId=" + tc.id.string() + " " + tc.comment
      let label: String val = consume label_iso

      if tc.valid then
        h.assert_eq[String](tc.mac, actual_hex, label)
        h.assert_true(verify, label)
      else
        h.assert_false(tc.mac == actual_hex, label)
        h.assert_false(verify, label)
      end

      count = count + 1
    end

    h.assert_eq[USize](174, count)
