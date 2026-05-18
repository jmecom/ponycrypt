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
    test(_TestAesKnownVectors)
    test(_TestWycheproofAesCbcPkcs5)
    test(_TestSecp256k1U256)
    test(_TestSecp256k1ModArithmetic)
    test(_TestSecp256k1ScalarArithmetic)
    test(_TestSecp256k1PointArithmetic)
    test(_TestSecp256k1PropertyCorpus)
    test(_TestEcdsaSecp256k1KnownVector)
    test(_TestOpenSslEcdsaSecp256k1Vectors)
    test(_TestWycheproofEcdsaSecp256k1P1363)
    test(_TestEcdsaSecp256k1NegativeCorpus)
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

class iso _TestAesKnownVectors is UnitTest
  fun name(): String => "aes/known-vectors"

  fun apply(h: TestHelper) ? =>
    _assert_aes(
      h,
      "2b7e151628aed2a6abf7158809cf4f3c",
      "6bc1bee22e409f96e93d7e117393172a",
      "3ad77bb40d7a3660a89ecaf32466ef97")?
    _assert_aes(
      h,
      "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      "6bc1bee22e409f96e93d7e117393172a",
      "bd334f1d6e45f25ff712a214571fa5cc")?
    _assert_aes(
      h,
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "6bc1bee22e409f96e93d7e117393172a",
      "f3eed1bdb5d2a03c064b5a7e3db181f8")?

    h.assert_error({()? =>
      pc.Aes.encrypt_block(pc.Hex.decode("00112233445566778899aabbccddeeff")?,
        "short")?
    })
    h.assert_error({()? =>
      pc.Aes.encrypt_block("short key",
        pc.Hex.decode("00112233445566778899aabbccddeeff")?)?
    })

  fun _assert_aes(
    h: TestHelper,
    key_hex: String,
    pt_hex: String,
    ct_hex: String)
    ?
  =>
    let key_iso = pc.Hex.decode(key_hex)?
    let key: Array[U8] val = consume key_iso
    let pt_iso = pc.Hex.decode(pt_hex)?
    let pt: Array[U8] val = consume pt_iso
    let ct_iso = pc.Hex.decode(ct_hex)?
    let ct: Array[U8] val = consume ct_iso

    h.assert_eq[String](ct_hex, pc.Hex.encode(pc.Aes.encrypt_block(key, pt)?))
    h.assert_eq[String](pt_hex, pc.Hex.encode(pc.Aes.decrypt_block(key, ct)?))

class iso _TestWycheproofAesCbcPkcs5 is UnitTest
  fun name(): String => "wycheproof/aes-cbc-pkcs5"

  fun apply(h: TestHelper) ? =>
    var count: USize = 0
    var valid_count: USize = 0
    var invalid_count: USize = 0

    for tc in WycheproofAesCbcPkcs5Vectors().values() do
      let key_iso = pc.Hex.decode(tc.key)?
      let key: Array[U8] val = consume key_iso
      let iv_iso = pc.Hex.decode(tc.iv)?
      let iv: Array[U8] val = consume iv_iso
      let msg_iso = pc.Hex.decode(tc.msg)?
      let msg: Array[U8] val = consume msg_iso
      let ct_iso = pc.Hex.decode(tc.ct)?
      let ct: Array[U8] val = consume ct_iso
      let label_iso = "tcId=" + tc.id.string() + " " + tc.comment
      let label: String val = consume label_iso

      if tc.valid then
        h.assert_eq[String](
          tc.ct,
          pc.Hex.encode(AesCbcPkcs5ForTest.encrypt(key, iv, msg)?),
          label)
        h.assert_eq[String](
          tc.msg,
          pc.Hex.encode(AesCbcPkcs5ForTest.decrypt(key, iv, ct)?),
          label)
        valid_count = valid_count + 1
      else
        h.assert_error({()? =>
          AesCbcPkcs5ForTest.decrypt(key, iv, ct)?
        }, label)
        invalid_count = invalid_count + 1
      end

      count = count + 1
    end

    h.assert_eq[USize](216, count)
    h.assert_eq[USize](72, valid_count)
    h.assert_eq[USize](144, invalid_count)

class iso _TestEcdsaSecp256k1KnownVector is UnitTest
  fun name(): String => "ecdsa-secp256k1/known-vector"

  fun apply(h: TestHelper) ? =>
    let private_key = _hex(
      "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f")?
    let nonce = _hex(
      "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a")?
    let digest = _hex(
      "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")?
    let public_key_hex_iso =
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd" +
      "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f"
    let public_key_hex: String val = consume public_key_hex_iso
    let signature_hex_iso =
      "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795" +
      "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
    let signature_hex: String val = consume signature_hex_iso

    let public_key = pc.EcdsaSecp256k1.public_key(private_key)?
    h.assert_eq[String](
      public_key_hex,
      pc.Hex.encode(public_key.to_uncompressed()))

    let parsed_public_key = pc.EcdsaSecp256k1.public_key_from_uncompressed(
      _hex(public_key_hex)?)?
    let signature = pc.EcdsaSecp256k1.sign_digest_with_k(
      private_key,
      digest,
      nonce)?
    h.assert_eq[String](signature_hex, pc.Hex.encode(signature.to_bytes()))
    h.assert_true(pc.EcdsaSecp256k1.verify_digest(
      parsed_public_key,
      digest,
      signature))

    let deterministic = pc.EcdsaSecp256k1.sign_digest(private_key, digest)?
    h.assert_true(pc.EcdsaSecp256k1.verify_digest(
      parsed_public_key,
      digest,
      deterministic))

    let bad_signature = pc.EcdsaSecp256k1.signature_from_bytes(_hex(
      "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795" +
      "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0f")?)?
    h.assert_false(pc.EcdsaSecp256k1.verify_digest(
      parsed_public_key,
      digest,
      bad_signature))

  fun _hex(data: String box): Array[U8] val ? =>
    let iso_data = pc.Hex.decode(data)?
    consume iso_data

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
