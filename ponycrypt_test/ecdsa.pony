use "pony_test"
use pc = "ponycrypt"

primitive _EcdsaHex
  fun bytes(data: String box): Array[U8] val ? =>
    let iso_data = pc.Hex.decode(data)?
    consume iso_data

  fun u256(data: String box): pc.U256 ? =>
    pc.Secp256k1MathForTest.u256_from_hex(data)?

  fun label(prefix: String, id: USize, comment: String): String val =>
    let iso_label = prefix + " tcId=" + id.string() + " " + comment
    consume iso_label

class iso _TestOpenSslEcdsaSecp256k1Vectors is UnitTest
  fun name(): String => "ecdsa-secp256k1/openssl-vectors"

  fun apply(h: TestHelper) ? =>
    var count: USize = 0

    for tc in OpenSslEcdsaSecp256k1Vectors().values() do
      let label = _EcdsaHex.label("openssl", tc.id, tc.comment)
      let private_key = _EcdsaHex.bytes(tc.private_key)?
      let msg = _EcdsaHex.bytes(tc.msg)?
      let digest = pc.Sha256.digest(msg)
      let public_key = pc.EcdsaSecp256k1.public_key(private_key)?
      let signature = pc.EcdsaSecp256k1.sign_digest(private_key, digest)?
      let parsed_signature =
        pc.EcdsaSecp256k1.signature_from_bytes(_EcdsaHex.bytes(tc.signature)?)?

      h.assert_eq[String](
        tc.digest,
        pc.Hex.encode(digest),
        label)
      h.assert_eq[String](
        tc.public_key,
        pc.Hex.encode(public_key.to_uncompressed()),
        label)
      h.assert_eq[String](
        tc.signature,
        pc.Hex.encode(signature.to_bytes()),
        label)
      h.assert_true(
        pc.EcdsaSecp256k1.verify_digest(public_key, digest, parsed_signature),
        label)

      count = count + 1
    end

    h.assert_eq[USize](33, count)

class iso _TestWycheproofEcdsaSecp256k1P1363 is UnitTest
  fun name(): String => "wycheproof/ecdsa-secp256k1-sha256-p1363"

  fun apply(h: TestHelper) =>
    var count: USize = 0
    var valid_count: USize = 0
    var invalid_count: USize = 0

    for tc in WycheproofEcdsaSecp256k1P1363Vectors().values() do
      let label = _EcdsaHex.label("wycheproof", tc.id, tc.comment)
      let accepted = _verify_case(tc.public_key, tc.msg, tc.sig)

      if tc.valid then
        h.assert_true(accepted, label)
        valid_count = valid_count + 1
      else
        h.assert_false(accepted, label)
        invalid_count = invalid_count + 1
      end

      count = count + 1
    end

    h.assert_eq[USize](252, count)
    h.assert_eq[USize](167, valid_count)
    h.assert_eq[USize](85, invalid_count)

  fun _verify_case(
    public_key_hex: String,
    msg_hex: String,
    sig_hex: String)
    : Bool
  =>
    try
      let public_key = pc.EcdsaSecp256k1.public_key_from_uncompressed(
        _EcdsaHex.bytes(public_key_hex)?)?
      let msg = _EcdsaHex.bytes(msg_hex)?
      let digest = pc.Sha256.digest(msg)
      let signature = pc.EcdsaSecp256k1.signature_from_bytes(
        _EcdsaHex.bytes(sig_hex)?)?
      pc.EcdsaSecp256k1.verify_digest(public_key, digest, signature)
    else
      false
    end

class iso _TestEcdsaSecp256k1NegativeCorpus is UnitTest
  fun name(): String => "ecdsa-secp256k1/negative-corpus"

  fun apply(h: TestHelper) ? =>
    let private_key = _EcdsaHex.bytes(
      "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f")?
    let digest = _EcdsaHex.bytes(
      "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")?
    let wrong_digest = _EcdsaHex.bytes(
      "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1b")?
    let nonce = _EcdsaHex.bytes(
      "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a")?
    let signature = pc.EcdsaSecp256k1.sign_digest_with_k(
      private_key,
      digest,
      nonce)?
    let public_key = pc.EcdsaSecp256k1.public_key(private_key)?
    let wrong_key = pc.EcdsaSecp256k1.public_key(_EcdsaHex.bytes(
      "0000000000000000000000000000000000000000000000000000000000000002")?)?

    h.assert_false(pc.EcdsaSecp256k1.verify_digest(
      public_key,
      wrong_digest,
      signature),
      "wrong digest")
    h.assert_false(pc.EcdsaSecp256k1.verify_digest(
      wrong_key,
      digest,
      signature),
      "wrong public key")

    let high_s = pc.Secp256k1MathForTest.scalar_mul(
      signature.s,
      _EcdsaHex.u256(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?)
    h.assert_false(
      pc.Secp256k1MathForTest.u256_eq(signature.s, high_s),
      "high-S changes signature")
    h.assert_true(pc.EcdsaSecp256k1.verify_digest(
      public_key,
      digest,
      pc.Secp256k1Signature(signature.r, high_s)),
      "generic ECDSA accepts high-S equivalent")

    _assert_signature_error(h, "", "empty signature")
    _assert_signature_error(h, "00", "short signature")
    _assert_signature_error(h,
      "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795" +
      "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e00",
      "long signature")
    _assert_signature_error(h,
      "0000000000000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000000000000000000000000000001",
      "r zero")
    _assert_signature_error(h,
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "0000000000000000000000000000000000000000000000000000000000000000",
      "s zero")
    _assert_signature_error(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" +
      "0000000000000000000000000000000000000000000000000000000000000001",
      "r equals n")
    _assert_signature_error(h,
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      "s equals n")

    _assert_public_key_error(h, "04", "truncated public key")
    _assert_public_key_error(h,
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "compressed public key")
    _assert_public_key_error(h,
      "0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      "bad public key prefix")
    _assert_public_key_error(h,
      "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f" +
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      "x equals p")
    _assert_public_key_error(h,
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
      "y equals p")
    _assert_public_key_error(h,
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b7",
      "off-curve public key")

    h.assert_error({()? => pc.EcdsaSecp256k1.public_key(_EcdsaHex.bytes(
      "0000000000000000000000000000000000000000000000000000000000000000")?)? },
      "zero private key")
    h.assert_error({()? => pc.EcdsaSecp256k1.public_key(_EcdsaHex.bytes(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)? },
      "private key equals n")
    h.assert_error({()? => pc.EcdsaSecp256k1.sign_digest_with_k(
      private_key,
      digest,
      _EcdsaHex.bytes(
        "0000000000000000000000000000000000000000000000000000000000000000")?)? },
      "zero nonce")
    h.assert_error({()? => pc.EcdsaSecp256k1.sign_digest_with_k(
      private_key,
      digest,
      _EcdsaHex.bytes(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)? },
      "nonce equals n")

  fun _assert_signature_error(
    h: TestHelper,
    signature_hex: String,
    msg: String)
  =>
    h.assert_error({()? =>
      pc.EcdsaSecp256k1.signature_from_bytes(_EcdsaHex.bytes(signature_hex)?)?
    }, msg)

  fun _assert_public_key_error(
    h: TestHelper,
    public_key_hex: String,
    msg: String)
  =>
    h.assert_error({()? =>
      pc.EcdsaSecp256k1.public_key_from_uncompressed(
        _EcdsaHex.bytes(public_key_hex)?)?
    }, msg)
