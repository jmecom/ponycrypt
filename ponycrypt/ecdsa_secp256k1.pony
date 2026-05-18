use "collections"

class val Secp256k1PublicKey
  let x: U256
  let y: U256

  new val create(x': U256, y': U256) =>
    x = x'
    y = y'

  fun to_uncompressed(): Array[U8] val =>
    recover val
      let out = Array[U8](65)
      out.push(0x04)
      _U256.push_bytes(out, x)
      _U256.push_bytes(out, y)
      out
    end

class val Secp256k1Signature
  let r: U256
  let s: U256

  new val create(r': U256, s': U256) =>
    r = r'
    s = s'

  fun to_bytes(): Array[U8] val =>
    recover val
      let out = Array[U8](64)
      _U256.push_bytes(out, r)
      _U256.push_bytes(out, s)
      out
    end

primitive EcdsaSecp256k1
  """
  ECDSA over secp256k1 using SHA-256 sized digests.

  This is an experimental pure-Pony implementation. It is not yet written as
  constant-time scalar arithmetic.
  """
  fun public_key(private_key: ReadSeq[U8]): Secp256k1PublicKey ? =>
    let d = _Scalar.from_bytes(private_key)?
    _Secp256k1.to_affine(_Secp256k1.scalar_mul_base(d))?

  fun sign_digest(private_key: ReadSeq[U8], digest: ReadSeq[U8])
    : Secp256k1Signature ?
  =>
    let nonce = _Rfc6979Secp256k1.nonce(private_key, digest)?
    sign_digest_with_k(private_key, digest, _U256.to_bytes(nonce))?

  fun sign_digest_with_k(
    private_key: ReadSeq[U8],
    digest: ReadSeq[U8],
    nonce: ReadSeq[U8])
    : Secp256k1Signature ?
  =>
    let d = _Scalar.from_bytes(private_key)?
    let z = _Scalar.from_digest(digest)?
    let k = _Scalar.from_bytes(nonce)?

    let r_point = _Secp256k1.to_affine(_Secp256k1.scalar_mul_base(k))?
    let r = _Scalar.reduce_field(r_point.x)
    if _U256.is_zero(r) then error end

    let kinv = _Scalar.inv(k)
    let rd = _Scalar.mul(r, d)
    let s = _Scalar.mul(kinv, _Scalar.add(z, rd))
    if _U256.is_zero(s) then error end

    Secp256k1Signature(r, s)

  fun verify_digest(
    key: Secp256k1PublicKey,
    digest: ReadSeq[U8],
    signature: Secp256k1Signature)
    : Bool
  =>
    try
      if not _Secp256k1.is_on_curve(key) then
        return false
      end

      if (not _Scalar.is_valid(signature.r)) or
        (not _Scalar.is_valid(signature.s))
      then
        return false
      end

      let z = _Scalar.from_digest(digest)?
      let w = _Scalar.inv(signature.s)
      let u1 = _Scalar.mul(z, w)
      let u2 = _Scalar.mul(signature.r, w)

      let p1 = _Secp256k1.scalar_mul_base(u1)
      let p2 = _Secp256k1.scalar_mul(key, u2)
      let sum = _Point.add(p1, p2)

      if sum.infinity then
        return false
      end

      let affine = _Secp256k1.to_affine(sum)?
      _U256.eq(_Scalar.reduce_field(affine.x), signature.r)
    else
      false
    end

  fun public_key_from_uncompressed(data: ReadSeq[U8])
    : Secp256k1PublicKey ?
  =>
    if (data.size() != 65) or (data(0)? != 0x04) then
      error
    end

    let x = _U256.from_bytes_at(data, 1)?
    let y = _U256.from_bytes_at(data, 33)?
    let key = Secp256k1PublicKey(x, y)

    if not _Secp256k1.is_on_curve(key) then
      error
    end

    key

  fun signature_from_bytes(data: ReadSeq[U8]): Secp256k1Signature ? =>
    if data.size() != 64 then
      error
    end

    let signature = Secp256k1Signature(
      _U256.from_bytes_at(data, 0)?,
      _U256.from_bytes_at(data, 32)?)

    if (not _Scalar.is_valid(signature.r)) or
      (not _Scalar.is_valid(signature.s))
    then
      error
    end

    signature

primitive _Secp256k1Constants
  fun p(): U256 =>
    U256(
      0xfffffffefffffc2f,
      0xffffffffffffffff,
      0xffffffffffffffff,
      0xffffffffffffffff)

  fun p_minus_2(): U256 =>
    U256(
      0xfffffffefffffc2d,
      0xffffffffffffffff,
      0xffffffffffffffff,
      0xffffffffffffffff)

  fun n(): U256 =>
    U256(
      0xbfd25e8cd0364141,
      0xbaaedce6af48a03b,
      0xfffffffffffffffe,
      0xffffffffffffffff)

  fun n_minus_2(): U256 =>
    U256(
      0xbfd25e8cd036413f,
      0xbaaedce6af48a03b,
      0xfffffffffffffffe,
      0xffffffffffffffff)

  fun gx(): U256 =>
    U256(
      0x59f2815b16f81798,
      0x029bfcdb2dce28d9,
      0x55a06295ce870b07,
      0x79be667ef9dcbbac)

  fun gy(): U256 =>
    U256(
      0x9c47d08ffb10d4b8,
      0xfd17b448a6855419,
      0x5da4fbfc0e1108a8,
      0x483ada7726a3c465)

primitive Secp256k1MathForTest
  fun u256_from_hex(data: String box): U256 ? =>
    let bytes_iso = Hex.decode(data)?
    let bytes: Array[U8] val = consume bytes_iso
    _U256.from_bytes(bytes)?

  fun u256_from_bytes(data: ReadSeq[U8]): U256 ? =>
    _U256.from_bytes(data)?

  fun u256_hex(value: U256): String iso^ =>
    Hex.encode(_U256.to_bytes(value))

  fun u256_is_zero(value: U256): Bool =>
    _U256.is_zero(value)

  fun u256_eq(a: U256, b: U256): Bool =>
    _U256.eq(a, b)

  fun u256_cmp(a: U256, b: U256): I8 =>
    _U256.cmp(a, b)

  fun u256_gte(a: U256, b: U256): Bool =>
    _U256.gte(a, b)

  fun u256_bit(a: U256, i: USize): Bool =>
    _U256.bit(a, i)

  fun u256_add_raw(a: U256, b: U256): (U256, Bool) =>
    _U256.add_raw(a, b)

  fun u256_sub_raw(a: U256, b: U256): (U256, Bool) =>
    _U256.sub_raw(a, b)

  fun p(): U256 =>
    _Secp256k1Constants.p()

  fun n(): U256 =>
    _Secp256k1Constants.n()

  fun field_add(a: U256, b: U256): U256 =>
    _Field.add(a, b)

  fun field_sub(a: U256, b: U256): U256 =>
    _Field.sub(a, b)

  fun field_mul(a: U256, b: U256): U256 =>
    _Field.mul(a, b)

  fun field_square(a: U256): U256 =>
    _Field.square(a)

  fun field_inv(a: U256): U256 =>
    _Field.inv(a)

  fun scalar_add(a: U256, b: U256): U256 =>
    _Scalar.add(a, b)

  fun scalar_mul(a: U256, b: U256): U256 =>
    _Scalar.mul(a, b)

  fun scalar_inv(a: U256): U256 =>
    _Scalar.inv(a)

  fun scalar_from_bytes(data: ReadSeq[U8]): U256 ? =>
    _Scalar.from_bytes(data)?

  fun scalar_from_digest(data: ReadSeq[U8]): U256 ? =>
    _Scalar.from_digest(data)?

  fun scalar_is_valid(value: U256): Bool =>
    _Scalar.is_valid(value)

  fun generator(): Secp256k1PublicKey =>
    _Secp256k1.generator()

  fun scalar_mul_base(k: U256): Secp256k1PublicKey ? =>
    _Secp256k1.to_affine(_Secp256k1.scalar_mul_base(k))?

  fun scalar_mul_base_is_infinity(k: U256): Bool =>
    _Secp256k1.scalar_mul_base(k).infinity

  fun point_add(a: Secp256k1PublicKey, b: Secp256k1PublicKey)
    : Secp256k1PublicKey ?
  =>
    _Secp256k1.to_affine(_Point.add(_jacobian(a), _jacobian(b)))?

  fun point_add_is_infinity(
    a: Secp256k1PublicKey,
    b: Secp256k1PublicKey)
    : Bool
  =>
    _Point.add(_jacobian(a), _jacobian(b)).infinity

  fun point_double(a: Secp256k1PublicKey): Secp256k1PublicKey ? =>
    _Secp256k1.to_affine(_Point.double(_jacobian(a)))?

  fun point_is_on_curve(a: Secp256k1PublicKey): Bool =>
    _Secp256k1.is_on_curve(a)

  fun public_key(x: U256, y: U256): Secp256k1PublicKey =>
    Secp256k1PublicKey(x, y)

  fun public_key_hex(key: Secp256k1PublicKey): String iso^ =>
    Hex.encode(key.to_uncompressed())

  fun _jacobian(key: Secp256k1PublicKey): _JacobianPoint =>
    _JacobianPoint(key.x, key.y, _U256.one())

primitive _Rfc6979Secp256k1
  fun nonce(private_key: ReadSeq[U8], digest: ReadSeq[U8]): U256 ? =>
    let x = _Scalar.from_bytes(private_key)?
    let h = _Scalar.bits2octets(digest)?
    let x_bytes = _U256.to_bytes(x)
    let h_bytes = _U256.to_bytes(h)

    var k: Array[U8] val = _fill(0x00, 32)
    var v: Array[U8] val = _fill(0x01, 32)

    k = Hmac[Sha256].digest(k, _concat_v_x_h(v, 0x00, x_bytes, h_bytes))
    v = Hmac[Sha256].digest(k, v)
    k = Hmac[Sha256].digest(k, _concat_v_x_h(v, 0x01, x_bytes, h_bytes))
    v = Hmac[Sha256].digest(k, v)

    while true do
      v = Hmac[Sha256].digest(k, v)
      let candidate = _U256.from_bytes(v)?
      if _Scalar.is_valid(candidate) then
        return candidate
      end
      k = Hmac[Sha256].digest(k, _concat_v(v, 0x00))
      v = Hmac[Sha256].digest(k, v)
    end

    error

  fun _fill(byte: U8, len: USize): Array[U8] val =>
    recover val
      let out = Array[U8](len)
      for i in Range[USize](0, len) do
        out.push(byte)
      end
      out
    end

  fun _concat_v_x_h(
    v: ReadSeq[U8] val,
    marker: U8,
    x: ReadSeq[U8] val,
    h: ReadSeq[U8] val)
    : Array[U8] val
  =>
    recover val
      let out = Array[U8](v.size() + 1 + x.size() + h.size())
      _copy(out, v)
      out.push(marker)
      _copy(out, x)
      _copy(out, h)
      out
    end

  fun _concat_v(v: ReadSeq[U8] val, marker: U8): Array[U8] val =>
    recover val
      let out = Array[U8](v.size() + 1)
      _copy(out, v)
      out.push(marker)
      out
    end

  fun _copy(out: Array[U8] ref, data: ReadSeq[U8] val) =>
    for b in data.values() do
      out.push(b)
    end
