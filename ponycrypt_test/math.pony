use "pony_test"
use pc = "ponycrypt"

primitive _MathHex
  fun u256(data: String box): pc.U256 ? =>
    pc.Secp256k1MathForTest.u256_from_hex(data)?

  fun bytes(data: String box): Array[U8] val ? =>
    let iso_data = pc.Hex.decode(data)?
    consume iso_data

  fun assert_u256(
    h: TestHelper,
    expected: String,
    actual: pc.U256,
    msg: String = "")
  =>
    h.assert_eq[String](
      expected,
      pc.Secp256k1MathForTest.u256_hex(actual),
      msg)

  fun assert_point(
    h: TestHelper,
    key: pc.Secp256k1PublicKey,
    expected_x: String,
    expected_y: String,
    msg: String = "")
  =>
    assert_u256(h, expected_x, key.x, msg + " x")
    assert_u256(h, expected_y, key.y, msg + " y")

  fun assert_point_eq(
    h: TestHelper,
    actual: pc.Secp256k1PublicKey,
    expected: pc.Secp256k1PublicKey,
    msg: String = "")
  =>
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(actual.x, expected.x),
      msg + " x")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(actual.y, expected.y),
      msg + " y")

class iso _TestSecp256k1U256 is UnitTest
  fun name(): String => "secp256k1-math/u256"

  fun apply(h: TestHelper) ? =>
    _round_trip(h,
      "0000000000000000000000000000000000000000000000000000000000000000")?
    _round_trip(h,
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _round_trip(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")?
    _round_trip(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?
    _round_trip(h,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?
    _round_trip(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")?
    _round_trip(h,
      "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321")?

    h.assert_error({()? => _MathHex.u256("00")? })
    h.assert_error({()? => _MathHex.u256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")? })

    let zero = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?
    let one = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?
    let high = _MathHex.u256(
      "8000000000000000000000000000000000000000000000000000000000000000")?
    let max = _MathHex.u256(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?

    h.assert_true(pc.Secp256k1MathForTest.u256_is_zero(zero))
    h.assert_false(pc.Secp256k1MathForTest.u256_is_zero(one))
    h.assert_eq[I8](-1, pc.Secp256k1MathForTest.u256_cmp(zero, one))
    h.assert_eq[I8](0, pc.Secp256k1MathForTest.u256_cmp(one, one))
    h.assert_eq[I8](1, pc.Secp256k1MathForTest.u256_cmp(max, high))
    h.assert_true(pc.Secp256k1MathForTest.u256_gte(max, high))
    h.assert_false(pc.Secp256k1MathForTest.u256_gte(one, max))
    h.assert_true(pc.Secp256k1MathForTest.u256_bit(one, 0))
    h.assert_false(pc.Secp256k1MathForTest.u256_bit(one, 1))
    h.assert_true(pc.Secp256k1MathForTest.u256_bit(high, 255))
    h.assert_false(pc.Secp256k1MathForTest.u256_bit(high, 254))

    _raw(h,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      false,
      "0000000000000000000000000000000000000000000000000000000000000000",
      false)?
    _raw(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005",
      false,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      true)?
    _raw(h,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000",
      true,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
      false)?
    _raw(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0",
      "0000000000000000000000000000000000000000000000000123456789abcdef",
      "0000000000000000000000000000000000000000000000000123456789abcddf",
      true,
      "fffffffffffffffffffffffffffffffffffffffffffffffffedcba9876543201",
      false)?
    _raw(h,
      "8000000000000000000000000000000000000000000000000000000000000000",
      "8000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      true,
      "0000000000000000000000000000000000000000000000000000000000000000",
      false)?
    _raw(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
      "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321",
      "2222222222222211222222222222221122222222222222112222222222222211",
      false,
      "02468acf13579bcf02468acf13579bcf02468acf13579bcf02468acf13579bcf",
      false)?

  fun _round_trip(h: TestHelper, value: String) ? =>
    _MathHex.assert_u256(h, value, _MathHex.u256(value)?)

  fun _raw(
    h: TestHelper,
    a_hex: String,
    b_hex: String,
    sum_hex: String,
    carry: Bool,
    diff_hex: String,
    borrow: Bool)
    ?
  =>
    let a = _MathHex.u256(a_hex)?
    let b = _MathHex.u256(b_hex)?
    (let sum, let actual_carry) =
      pc.Secp256k1MathForTest.u256_add_raw(a, b)
    (let diff, let actual_borrow) =
      pc.Secp256k1MathForTest.u256_sub_raw(a, b)
    _MathHex.assert_u256(h, sum_hex, sum, "raw add")
    h.assert_eq[Bool](carry, actual_carry, "raw add carry")
    _MathHex.assert_u256(h, diff_hex, diff, "raw sub")
    h.assert_eq[Bool](borrow, actual_borrow, "raw sub borrow")

class iso _TestSecp256k1ModArithmetic is UnitTest
  fun name(): String => "secp256k1-math/field"

  fun apply(h: TestHelper) ? =>
    _field(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _field(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
      "0000000000000000000000000000000000000000000000000000000000000006")?
    _field(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")?
    _field(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2a",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc29")?
    _field(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
      "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321",
      "2222222222222211222222222222221122222222222222112222222222222211",
      "02468acf13579bcf02468acf13579bcf02468acf13579bcf02468acf13579bcf",
      "8c644419c8c50984e1e06f7bc8ebdb3c375c9addc912acf38dfac0488d5f655d")?

    _field_inv(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18")?
    _field_inv(h,
      "0000000000000000000000000000000000000000000000000000000000000003",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd75")?
    _field_inv(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")?
    _field_inv(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
      "df37164d6ff61ed527289824f2aac8343ca55b3c9eeabe44cd6379abec0ba57c")?

    _field_laws(h,
      "0000000000000000000000000000000000000000000000000000000000000005",
      "0000000000000000000000000000000000000000000000000000000000000007",
      "000000000000000000000000000000000000000000000000000000000000000b")?
    _field_laws(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
      "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321",
      "0000000000000000000000000000000000000000000000000000000000000011")?
    _field_laws(h,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _field_laws(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005")?
    _field_laws(h,
      "6d6f3b7b2d9249f4cfa3382f29d0b5247c6f3f1c54e5a9d7aa19b1d8c3a4f579",
      "b0a6d0ec4b31f4a50f1a0b4f13f0af45b2a7c9d61b0a651d1297d2b87f0a8d93",
      "27c9a5e2d81f3c4b5a69788766554433221100ffeeddccbbaa99887766554433")?

    _field_identities(h,
      "0000000000000000000000000000000000000000000000000000000000000000")?
    _field_identities(h,
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _field_identities(h,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")?
    _field_identities(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")?

  fun _field(
    h: TestHelper,
    a_hex: String,
    b_hex: String,
    add_hex: String,
    sub_hex: String,
    mul_hex: String)
    ?
  =>
    let a = _MathHex.u256(a_hex)?
    let b = _MathHex.u256(b_hex)?
    _MathHex.assert_u256(h, add_hex, pc.Secp256k1MathForTest.field_add(a, b), "field add")
    _MathHex.assert_u256(h, sub_hex, pc.Secp256k1MathForTest.field_sub(a, b), "field sub")
    _MathHex.assert_u256(h, mul_hex, pc.Secp256k1MathForTest.field_mul(a, b), "field mul")

  fun _field_inv(h: TestHelper, value_hex: String, inv_hex: String) ? =>
    let value = _MathHex.u256(value_hex)?
    let inv = pc.Secp256k1MathForTest.field_inv(value)
    _MathHex.assert_u256(h, inv_hex, inv, "field inv")
    _MathHex.assert_u256(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      pc.Secp256k1MathForTest.field_mul(value, inv),
      "field inv identity")

  fun _field_laws(h: TestHelper, a_hex: String, b_hex: String, c_hex: String) ? =>
    let a = _MathHex.u256(a_hex)?
    let b = _MathHex.u256(b_hex)?
    let c = _MathHex.u256(c_hex)?
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.field_add(a, b),
      pc.Secp256k1MathForTest.field_add(b, a)),
      "field add commutes")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.field_mul(a, b),
      pc.Secp256k1MathForTest.field_mul(b, a)),
      "field mul commutes")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.field_add(
        pc.Secp256k1MathForTest.field_add(a, b), c),
      pc.Secp256k1MathForTest.field_add(
        a, pc.Secp256k1MathForTest.field_add(b, c))),
      "field add associates")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.field_mul(
        pc.Secp256k1MathForTest.field_add(a, b), c),
      pc.Secp256k1MathForTest.field_add(
        pc.Secp256k1MathForTest.field_mul(a, c),
        pc.Secp256k1MathForTest.field_mul(b, c))),
      "field distributive")

  fun _field_identities(h: TestHelper, value_hex: String) ? =>
    let zero = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?
    let one = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?
    let value = _MathHex.u256(value_hex)?

    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      value,
      pc.Secp256k1MathForTest.field_add(value, zero)),
      "field add zero")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      zero,
      pc.Secp256k1MathForTest.field_sub(value, value)),
      "field subtract self")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      value,
      pc.Secp256k1MathForTest.field_mul(value, one)),
      "field mul one")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.field_square(value),
      pc.Secp256k1MathForTest.field_mul(value, value)),
      "field square matches mul")

class iso _TestSecp256k1ScalarArithmetic is UnitTest
  fun name(): String => "secp256k1-math/scalar"

  fun apply(h: TestHelper) ? =>
    h.assert_false(pc.Secp256k1MathForTest.scalar_is_valid(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?))
    h.assert_true(pc.Secp256k1MathForTest.scalar_is_valid(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?))
    h.assert_true(pc.Secp256k1MathForTest.scalar_is_valid(_MathHex.u256(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?))
    h.assert_false(pc.Secp256k1MathForTest.scalar_is_valid(_MathHex.u256(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?))

    h.assert_error({()? => pc.Secp256k1MathForTest.scalar_from_bytes(_MathHex.bytes(
      "0000000000000000000000000000000000000000000000000000000000000000")?)? })
    h.assert_error({()? => pc.Secp256k1MathForTest.scalar_from_bytes(_MathHex.bytes(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)? })

    _scalar(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      "0000000000000000000000000000000000000000000000000000000000000006")?
    _scalar(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f")?
    _scalar(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
      "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321",
      "2222222222222211222222222222221122222222222222112222222222222211",
      "02468acf13579bcf02468acf13579bcf02468acf13579bcf02468acf13579bcf",
      "a5393281d581eac38aa0b5b7a460398562c086099ee7fe5700c013d19c7b1d99")?

    _scalar_inv(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1")?
    _scalar_inv(h,
      "0000000000000000000000000000000000000000000000000000000000000003",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9d1c9e899ca306ad27fe1945de0242b81")?
    _scalar_inv(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?

    _digest(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      "0000000000000000000000000000000000000000000000000000000000000000")?
    _digest(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _digest(h,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe")?

    _scalar_laws(h,
      "0000000000000000000000000000000000000000000000000000000000000005",
      "0000000000000000000000000000000000000000000000000000000000000007",
      "000000000000000000000000000000000000000000000000000000000000000b")?
    _scalar_laws(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
      "0000000000000000000000000000000000000000000000000000000000000002")?
    _scalar_laws(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005")?
    _scalar_laws(h,
      "6d6f3b7b2d9249f4cfa3382f29d0b5247c6f3f1c54e5a9d7aa19b1d8c3a4f579",
      "10a6d0ec4b31f4a50f1a0b4f13f0af45b2a7c9d61b0a651d1297d2b87f0a8d93",
      "27c9a5e2d81f3c4b5a69788766554433221100ffeeddccbbaa99887766554433")?

    _scalar_identities(h,
      "0000000000000000000000000000000000000000000000000000000000000001")?
    _scalar_identities(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?
    _scalar_identities(h,
      "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")?

  fun _scalar(
    h: TestHelper,
    a_hex: String,
    b_hex: String,
    add_hex: String,
    sub_hex: String,
    mul_hex: String)
    ?
  =>
    let a = _MathHex.u256(a_hex)?
    let b = _MathHex.u256(b_hex)?
    _MathHex.assert_u256(h, add_hex, pc.Secp256k1MathForTest.scalar_add(a, b), "scalar add")
    _MathHex.assert_u256(h, sub_hex, pc.Secp256k1MathForTest.scalar_add(
      a, pc.Secp256k1MathForTest.scalar_mul(b, _MathHex.u256(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?)),
      "scalar sub via negative")
    _MathHex.assert_u256(h, mul_hex, pc.Secp256k1MathForTest.scalar_mul(a, b), "scalar mul")

  fun _scalar_inv(h: TestHelper, value_hex: String, inv_hex: String) ? =>
    let value = _MathHex.u256(value_hex)?
    let inv = pc.Secp256k1MathForTest.scalar_inv(value)
    _MathHex.assert_u256(h, inv_hex, inv, "scalar inv")
    _MathHex.assert_u256(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      pc.Secp256k1MathForTest.scalar_mul(value, inv),
      "scalar inv identity")

  fun _digest(h: TestHelper, digest_hex: String, expected_hex: String) ? =>
    _MathHex.assert_u256(
      h,
      expected_hex,
      pc.Secp256k1MathForTest.scalar_from_digest(_MathHex.bytes(digest_hex)?)?,
      "bits2octets")

  fun _scalar_laws(h: TestHelper, a_hex: String, b_hex: String, c_hex: String) ? =>
    let a = _MathHex.u256(a_hex)?
    let b = _MathHex.u256(b_hex)?
    let c = _MathHex.u256(c_hex)?
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.scalar_add(a, b),
      pc.Secp256k1MathForTest.scalar_add(b, a)),
      "scalar add commutes")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.scalar_mul(a, b),
      pc.Secp256k1MathForTest.scalar_mul(b, a)),
      "scalar mul commutes")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.scalar_add(
        pc.Secp256k1MathForTest.scalar_add(a, b), c),
      pc.Secp256k1MathForTest.scalar_add(
        a, pc.Secp256k1MathForTest.scalar_add(b, c))),
      "scalar add associates")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      pc.Secp256k1MathForTest.scalar_mul(
        pc.Secp256k1MathForTest.scalar_add(a, b), c),
      pc.Secp256k1MathForTest.scalar_add(
        pc.Secp256k1MathForTest.scalar_mul(a, c),
        pc.Secp256k1MathForTest.scalar_mul(b, c))),
      "scalar distributive")

  fun _scalar_identities(h: TestHelper, value_hex: String) ? =>
    let zero = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?
    let one = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?
    let value = _MathHex.u256(value_hex)?

    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      value,
      pc.Secp256k1MathForTest.scalar_add(value, zero)),
      "scalar add zero")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      value,
      pc.Secp256k1MathForTest.scalar_mul(value, one)),
      "scalar mul one")
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(
      zero,
      pc.Secp256k1MathForTest.scalar_mul(value, zero)),
      "scalar mul zero")

class iso _TestSecp256k1PointArithmetic is UnitTest
  fun name(): String => "secp256k1-math/points"

  fun apply(h: TestHelper) ? =>
    h.assert_true(pc.Secp256k1MathForTest.point_is_on_curve(
      pc.Secp256k1MathForTest.generator()))
    h.assert_false(pc.Secp256k1MathForTest.point_is_on_curve(
      pc.Secp256k1MathForTest.public_key(
        _MathHex.u256("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?,
        _MathHex.u256("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b7")?)))

    _point(h, "0000000000000000000000000000000000000000000000000000000000000001",
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000002",
      "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000003",
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
      "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000004",
      "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
      "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000005",
      "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
      "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6")?
    _point(h, "000000000000000000000000000000000000000000000000000000000000000a",
      "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
      "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000010",
      "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
      "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000080",
      "34ff3be4033f7a06696c3d09f7d1671cbcf55cd700535655647077456769a24e",
      "5d9d11623a236c553f6619d89832098c55df16c3e8f8b6818491067a73cc2f1a")?
    _point(h, "0000000000000000000000000000000000000000000000000000000000000100",
      "8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508",
      "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf")?

    let g = pc.Secp256k1MathForTest.generator()
    let two = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000002")?)?
    let three = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000003")?)?
    let five = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000005")?)?
    let seven = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000007")?)?
    let ten = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "000000000000000000000000000000000000000000000000000000000000000a")?)?

    _MathHex.assert_point_eq(h, pc.Secp256k1MathForTest.point_double(g)?, two, "2G")
    _MathHex.assert_point_eq(h, pc.Secp256k1MathForTest.point_add(g, two)?, three, "G+2G")
    _MathHex.assert_point_eq(h, pc.Secp256k1MathForTest.point_double(five)?, ten, "2*5G")
    _MathHex.assert_point_eq(h, pc.Secp256k1MathForTest.point_add(three, seven)?, ten, "3G+7G")

    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002")?
    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003")?
    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000005")?
    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000007",
      "000000000000000000000000000000000000000000000000000000000000000a")?
    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000005",
      "000000000000000000000000000000000000000000000000000000000000000a",
      "000000000000000000000000000000000000000000000000000000000000000f")?
    _point_add_law(h,
      "0000000000000000000000000000000000000000000000000000000000000010",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "0000000000000000000000000000000000000000000000000000000000000090")?
    _point_add_law(h,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?

    _point_double_law(h,
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002")?
    _point_double_law(h,
      "0000000000000000000000000000000000000000000000000000000000000005",
      "000000000000000000000000000000000000000000000000000000000000000a")?
    _point_double_law(h,
      "0000000000000000000000000000000000000000000000000000000000000010",
      "0000000000000000000000000000000000000000000000000000000000000020")?
    _point_double_law(h,
      "0000000000000000000000000000000000000000000000000000000000000080",
      "0000000000000000000000000000000000000000000000000000000000000100")?

    h.assert_true(pc.Secp256k1MathForTest.scalar_mul_base_is_infinity(
      _MathHex.u256("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?))
    let n_minus_one = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")?)?
    h.assert_true(pc.Secp256k1MathForTest.point_add_is_infinity(g, n_minus_one))

    h.assert_error({()? => pc.EcdsaSecp256k1.public_key_from_uncompressed(_MathHex.bytes("04")?)? })
    h.assert_error({()? => pc.EcdsaSecp256k1.public_key_from_uncompressed(_MathHex.bytes(
      "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")?)? })
    h.assert_error({()? => pc.EcdsaSecp256k1.public_key_from_uncompressed(_MathHex.bytes(
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")?)? })
    h.assert_error({()? => pc.EcdsaSecp256k1.public_key_from_uncompressed(_MathHex.bytes(
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980000000000000000000000000000000000000000000000000000000000000000")?)? })

  fun _point(
    h: TestHelper,
    k_hex: String,
    x_hex: String,
    y_hex: String)
    ?
  =>
    _MathHex.assert_point(
      h,
      pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(k_hex)?)?,
      x_hex,
      y_hex,
      "scalar multiple")

  fun _point_add_law(
    h: TestHelper,
    a_hex: String,
    b_hex: String,
    sum_hex: String)
    ?
  =>
    let a = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(a_hex)?)?
    let b = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(b_hex)?)?
    let sum = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(sum_hex)?)?

    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_add(a, b)?,
      sum,
      "point add law")
    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_add(b, a)?,
      sum,
      "point add commutes")

  fun _point_double_law(
    h: TestHelper,
    k_hex: String,
    double_hex: String)
    ?
  =>
    let k = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(k_hex)?)?
    let doubled =
      pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(double_hex)?)?

    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_double(k)?,
      doubled,
      "point double law")

class iso _TestSecp256k1PropertyCorpus is UnitTest
  fun name(): String => "secp256k1-math/property-corpus"

  fun apply(h: TestHelper) ? =>
    var field_count: USize = 0
    for tc in Secp256k1FieldPropertyVectors().values() do
      _field_case(h, tc, field_count < 8)?
      field_count = field_count + 1
    end
    h.assert_eq[USize](32, field_count, "field property vector count")

    var scalar_count: USize = 0
    for tc in Secp256k1ScalarPropertyVectors().values() do
      _scalar_case(h, tc, scalar_count < 8)?
      scalar_count = scalar_count + 1
    end
    h.assert_eq[USize](32, scalar_count, "scalar property vector count")

    var point_count: USize = 0
    for tc in Secp256k1PointPropertyVectors().values() do
      _point_case(h, tc)?
      point_count = point_count + 1
    end
    h.assert_eq[USize](16, point_count, "point property vector count")

  fun _field_case(
    h: TestHelper,
    tc: Secp256k1TripleCase,
    check_inverse: Bool)
    ?
  =>
    let zero = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?
    let one = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?
    let a = _MathHex.u256(tc.a)?
    let b = _MathHex.u256(tc.b)?
    let c = _MathHex.u256(tc.c)?

    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_add(a, b),
      pc.Secp256k1MathForTest.field_add(b, a),
      "field property add commutes")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_mul(a, b),
      pc.Secp256k1MathForTest.field_mul(b, a),
      "field property mul commutes")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_add(
        pc.Secp256k1MathForTest.field_add(a, b), c),
      pc.Secp256k1MathForTest.field_add(
        a, pc.Secp256k1MathForTest.field_add(b, c)),
      "field property add associates")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_mul(
        pc.Secp256k1MathForTest.field_mul(a, b), c),
      pc.Secp256k1MathForTest.field_mul(
        a, pc.Secp256k1MathForTest.field_mul(b, c)),
      "field property mul associates")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_mul(
        pc.Secp256k1MathForTest.field_add(a, b), c),
      pc.Secp256k1MathForTest.field_add(
        pc.Secp256k1MathForTest.field_mul(a, c),
        pc.Secp256k1MathForTest.field_mul(b, c)),
      "field property distributive")
    _assert_u256_eq(h,
      a,
      pc.Secp256k1MathForTest.field_sub(
        pc.Secp256k1MathForTest.field_add(a, b), b),
      "field property add/sub roundtrip")
    _assert_u256_eq(h,
      zero,
      pc.Secp256k1MathForTest.field_sub(a, a),
      "field property self sub")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.field_square(a),
      pc.Secp256k1MathForTest.field_mul(a, a),
      "field property square")

    if check_inverse then
      _assert_u256_eq(h,
        one,
        pc.Secp256k1MathForTest.field_mul(
          a, pc.Secp256k1MathForTest.field_inv(a)),
        "field property inverse")
    end

  fun _scalar_case(
    h: TestHelper,
    tc: Secp256k1TripleCase,
    check_inverse: Bool)
    ?
  =>
    let zero = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000000")?
    let one = _MathHex.u256(
      "0000000000000000000000000000000000000000000000000000000000000001")?
    let a = _MathHex.u256(tc.a)?
    let b = _MathHex.u256(tc.b)?
    let c = _MathHex.u256(tc.c)?

    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.scalar_add(a, b),
      pc.Secp256k1MathForTest.scalar_add(b, a),
      "scalar property add commutes")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.scalar_mul(a, b),
      pc.Secp256k1MathForTest.scalar_mul(b, a),
      "scalar property mul commutes")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.scalar_add(
        pc.Secp256k1MathForTest.scalar_add(a, b), c),
      pc.Secp256k1MathForTest.scalar_add(
        a, pc.Secp256k1MathForTest.scalar_add(b, c)),
      "scalar property add associates")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.scalar_mul(
        pc.Secp256k1MathForTest.scalar_mul(a, b), c),
      pc.Secp256k1MathForTest.scalar_mul(
        a, pc.Secp256k1MathForTest.scalar_mul(b, c)),
      "scalar property mul associates")
    _assert_u256_eq(h,
      pc.Secp256k1MathForTest.scalar_mul(
        pc.Secp256k1MathForTest.scalar_add(a, b), c),
      pc.Secp256k1MathForTest.scalar_add(
        pc.Secp256k1MathForTest.scalar_mul(a, c),
        pc.Secp256k1MathForTest.scalar_mul(b, c)),
      "scalar property distributive")
    _assert_u256_eq(h,
      a,
      pc.Secp256k1MathForTest.scalar_add(a, zero),
      "scalar property add zero")
    _assert_u256_eq(h,
      a,
      pc.Secp256k1MathForTest.scalar_mul(a, one),
      "scalar property mul one")
    _assert_u256_eq(h,
      zero,
      pc.Secp256k1MathForTest.scalar_mul(a, zero),
      "scalar property mul zero")

    if check_inverse then
      _assert_u256_eq(h,
        one,
        pc.Secp256k1MathForTest.scalar_mul(
          a, pc.Secp256k1MathForTest.scalar_inv(a)),
        "scalar property inverse")
    end

  fun _point_case(h: TestHelper, tc: Secp256k1PointPairCase) ? =>
    let a = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(tc.a)?)?
    let b = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(tc.b)?)?
    let sum = pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(tc.sum)?)?
    let double_a =
      pc.Secp256k1MathForTest.scalar_mul_base(_MathHex.u256(tc.double_a)?)?

    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_add(a, b)?,
      sum,
      "point property add")
    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_add(b, a)?,
      sum,
      "point property add commutes")
    _MathHex.assert_point_eq(
      h,
      pc.Secp256k1MathForTest.point_double(a)?,
      double_a,
      "point property double")

  fun _assert_u256_eq(
    h: TestHelper,
    expected: pc.U256,
    actual: pc.U256,
    msg: String)
  =>
    h.assert_true(pc.Secp256k1MathForTest.u256_eq(expected, actual), msg)
