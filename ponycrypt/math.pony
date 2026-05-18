use "collections"

class val U256
  """
  A small unsigned 256-bit integer type, stored as little-endian U64 limbs.
  """
  let w0: U64
  let w1: U64
  let w2: U64
  let w3: U64

  new val create(
    w0': U64 = 0,
    w1': U64 = 0,
    w2': U64 = 0,
    w3': U64 = 0)
  =>
    w0 = w0'
    w1 = w1'
    w2 = w2'
    w3 = w3'

primitive _U256
  fun zero(): U256 => U256

  fun one(): U256 => U256(1)

  fun from_u64(x: U64): U256 => U256(x)

  fun is_zero(a: U256): Bool =>
    (a.w0 == 0) and (a.w1 == 0) and (a.w2 == 0) and (a.w3 == 0)

  fun eq(a: U256, b: U256): Bool =>
    (a.w0 == b.w0) and (a.w1 == b.w1) and
      (a.w2 == b.w2) and (a.w3 == b.w3)

  fun cmp(a: U256, b: U256): I8 =>
    if a.w3 > b.w3 then
      1
    elseif a.w3 < b.w3 then
      -1
    elseif a.w2 > b.w2 then
      1
    elseif a.w2 < b.w2 then
      -1
    elseif a.w1 > b.w1 then
      1
    elseif a.w1 < b.w1 then
      -1
    elseif a.w0 > b.w0 then
      1
    elseif a.w0 < b.w0 then
      -1
    else
      0
    end

  fun gte(a: U256, b: U256): Bool =>
    cmp(a, b) >= 0

  fun bit(a: U256, i: USize): Bool =>
    if i < 64 then
      ((a.w0 >> i.u64()) and 1) == 1
    elseif i < 128 then
      ((a.w1 >> (i - 64).u64()) and 1) == 1
    elseif i < 192 then
      ((a.w2 >> (i - 128).u64()) and 1) == 1
    else
      ((a.w3 >> (i - 192).u64()) and 1) == 1
    end

  fun add_raw(a: U256, b: U256): (U256, Bool) =>
    let s0 = a.w0 + b.w0
    let c0 = s0 < a.w0

    let s1a = a.w1 + b.w1
    let c1a = s1a < a.w1
    let s1 = s1a + if c0 then U64(1) else U64(0) end
    let c1 = c1a or (s1 < s1a)

    let s2a = a.w2 + b.w2
    let c2a = s2a < a.w2
    let s2 = s2a + if c1 then U64(1) else U64(0) end
    let c2 = c2a or (s2 < s2a)

    let s3a = a.w3 + b.w3
    let c3a = s3a < a.w3
    let s3 = s3a + if c2 then U64(1) else U64(0) end
    let c3 = c3a or (s3 < s3a)

    (U256(s0, s1, s2, s3), c3)

  fun sub_raw(a: U256, b: U256): (U256, Bool) =>
    let d0 = a.w0 - b.w0
    let b0 = a.w0 < b.w0

    let rhs1 = b.w1 + if b0 then U64(1) else U64(0) end
    let rhs1_over = rhs1 < b.w1
    let d1 = a.w1 - rhs1
    let b1 = rhs1_over or (a.w1 < rhs1)

    let rhs2 = b.w2 + if b1 then U64(1) else U64(0) end
    let rhs2_over = rhs2 < b.w2
    let d2 = a.w2 - rhs2
    let b2 = rhs2_over or (a.w2 < rhs2)

    let rhs3 = b.w3 + if b2 then U64(1) else U64(0) end
    let rhs3_over = rhs3 < b.w3
    let d3 = a.w3 - rhs3
    let b3 = rhs3_over or (a.w3 < rhs3)

    (U256(d0, d1, d2, d3), b3)

  fun twos_complement(a: U256): U256 =>
    (let out, _) = add_raw(
      U256(
        a.w0 xor 0xffffffffffffffff,
        a.w1 xor 0xffffffffffffffff,
        a.w2 xor 0xffffffffffffffff,
        a.w3 xor 0xffffffffffffffff),
      one())
    out

  fun shift_right_one(a: U256): U256 =>
    U256(
      (a.w0 >> 1) or ((a.w1 and 1) << 63),
      (a.w1 >> 1) or ((a.w2 and 1) << 63),
      (a.w2 >> 1) or ((a.w3 and 1) << 63),
      a.w3 >> 1)

  fun from_bytes(data: ReadSeq[U8]): U256 ? =>
    if data.size() != 32 then
      error
    end
    from_bytes_at(data, 0)?

  fun from_bytes_at(data: ReadSeq[U8], offset: USize): U256 ? =>
    if data.size() < (offset + 32) then
      error
    end

    U256(
      _read_u64(data, offset + 24)?,
      _read_u64(data, offset + 16)?,
      _read_u64(data, offset + 8)?,
      _read_u64(data, offset)?)

  fun to_bytes(a: U256): Array[U8] val =>
    recover val
      let out = Array[U8](32)
      push_bytes(out, a)
      out
    end

  fun push_bytes(out: Array[U8] ref, a: U256) =>
    _push_u64(out, a.w3)
    _push_u64(out, a.w2)
    _push_u64(out, a.w1)
    _push_u64(out, a.w0)

  fun _read_u64(data: ReadSeq[U8], offset: USize): U64 ? =>
    var out: U64 = 0
    for i in Range[USize](0, 8) do
      out = (out << 8) or data(offset + i)?.u64()
    end
    out

  fun _push_u64(out: Array[U8] ref, word: U64) =>
    out.push((word >> 56).u8())
    out.push(((word >> 48) and 0xff).u8())
    out.push(((word >> 40) and 0xff).u8())
    out.push(((word >> 32) and 0xff).u8())
    out.push(((word >> 24) and 0xff).u8())
    out.push(((word >> 16) and 0xff).u8())
    out.push(((word >> 8) and 0xff).u8())
    out.push((word and 0xff).u8())

primitive _Mod
  fun add(a: U256, b: U256, m: U256): U256 =>
    (let sum, let carry) = _U256.add_raw(a, b)
    if carry then
      (let out, _) = _U256.add_raw(sum, _U256.twos_complement(m))
      out
    elseif _U256.gte(sum, m) then
      (let out, _) = _U256.sub_raw(sum, m)
      out
    else
      sum
    end

  fun sub(a: U256, b: U256, m: U256): U256 =>
    (let diff, let borrow) = _U256.sub_raw(a, b)
    if borrow then
      (let out, _) = _U256.add_raw(diff, m)
      out
    else
      diff
    end

  fun mul(a: U256, b: U256, m: U256): U256 =>
    var result = _U256.zero()
    var addend = a
    var n = b

    for i in Range[USize](0, 256) do
      if _U256.bit(n, 0) then
        result = add(result, addend, m)
      end
      addend = add(addend, addend, m)
      n = _U256.shift_right_one(n)
    end

    result

  fun pow(base: U256, exponent: U256, m: U256): U256 =>
    var result = _U256.one()
    var i: USize = 256

    while i > 0 do
      i = i - 1
      result = mul(result, result, m)
      if _U256.bit(exponent, i) then
        result = mul(result, base, m)
      end
    end

    result

primitive _Field
  fun p(): U256 => _Secp256k1Constants.p()
  fun add(a: U256, b: U256): U256 => _Mod.add(a, b, p())
  fun sub(a: U256, b: U256): U256 => _Mod.sub(a, b, p())
  fun mul(a: U256, b: U256): U256 => _Mod.mul(a, b, p())
  fun square(a: U256): U256 => mul(a, a)
  fun inv(a: U256): U256 =>
    _Mod.pow(a, _Secp256k1Constants.p_minus_2(), p())
  fun from_u64(x: U64): U256 => U256(x)

primitive _Scalar
  fun n(): U256 => _Secp256k1Constants.n()
  fun add(a: U256, b: U256): U256 => _Mod.add(a, b, n())
  fun mul(a: U256, b: U256): U256 => _Mod.mul(a, b, n())
  fun inv(a: U256): U256 =>
    _Mod.pow(a, _Secp256k1Constants.n_minus_2(), n())

  fun from_bytes(data: ReadSeq[U8]): U256 ? =>
    let out = _U256.from_bytes(data)?
    if not is_valid(out) then
      error
    end
    out

  fun from_digest(digest: ReadSeq[U8]): U256 ? =>
    if digest.size() != 32 then
      error
    end
    bits2octets(digest)?

  fun bits2octets(digest: ReadSeq[U8]): U256 ? =>
    let z = _U256.from_bytes(digest)?
    if _U256.gte(z, n()) then
      (let out, _) = _U256.sub_raw(z, n())
      out
    else
      z
    end

  fun reduce_field(x: U256): U256 =>
    if _U256.gte(x, n()) then
      (let out, _) = _U256.sub_raw(x, n())
      out
    else
      x
    end

  fun is_valid(x: U256): Bool =>
    (not _U256.is_zero(x)) and (_U256.cmp(x, n()) < 0)

class val _JacobianPoint
  let x: U256
  let y: U256
  let z: U256
  let infinity: Bool

  new val create(x': U256, y': U256, z': U256, infinity': Bool = false) =>
    x = x'
    y = y'
    z = z'
    infinity = infinity'

  new val infinity_point() =>
    x = _U256.zero()
    y = _U256.zero()
    z = _U256.zero()
    infinity = true

primitive _Point
  fun double(p: _JacobianPoint): _JacobianPoint =>
    if p.infinity or _U256.is_zero(p.y) then
      return _JacobianPoint.infinity_point()
    end

    let yy = _Field.square(p.y)
    let yyyy = _Field.square(yy)
    let xx = _Field.square(p.x)
    let s = _Field.mul(_Field.from_u64(4), _Field.mul(p.x, yy))
    let m = _Field.mul(_Field.from_u64(3), xx)
    let x3 = _Field.sub(_Field.square(m), _Field.add(s, s))
    let y3 = _Field.sub(
      _Field.mul(m, _Field.sub(s, x3)),
      _Field.mul(_Field.from_u64(8), yyyy))
    let z3 = _Field.mul(_Field.from_u64(2), _Field.mul(p.y, p.z))

    _JacobianPoint(x3, y3, z3)

  fun add(p: _JacobianPoint, q: _JacobianPoint): _JacobianPoint =>
    if p.infinity then
      return q
    end
    if q.infinity then
      return p
    end

    let z1z1 = _Field.square(p.z)
    let z2z2 = _Field.square(q.z)
    let u1 = _Field.mul(p.x, z2z2)
    let u2 = _Field.mul(q.x, z1z1)
    let s1 = _Field.mul(p.y, _Field.mul(q.z, z2z2))
    let s2 = _Field.mul(q.y, _Field.mul(p.z, z1z1))

    if _U256.eq(u1, u2) then
      if _U256.eq(s1, s2) then
        return double(p)
      else
        return _JacobianPoint.infinity_point()
      end
    end

    let h = _Field.sub(u2, u1)
    let i = _Field.square(_Field.add(h, h))
    let j = _Field.mul(h, i)
    let r = _Field.add(_Field.sub(s2, s1), _Field.sub(s2, s1))
    let v = _Field.mul(u1, i)
    let x3 = _Field.sub(_Field.sub(_Field.square(r), j), _Field.add(v, v))
    let y3 = _Field.sub(
      _Field.mul(r, _Field.sub(v, x3)),
      _Field.mul(_Field.add(s1, s1), j))
    let z3 = _Field.mul(
      _Field.sub(_Field.sub(_Field.square(_Field.add(p.z, q.z)), z1z1), z2z2),
      h)

    _JacobianPoint(x3, y3, z3)

primitive _Secp256k1
  fun generator(): Secp256k1PublicKey =>
    Secp256k1PublicKey(
      _Secp256k1Constants.gx(),
      _Secp256k1Constants.gy())

  fun scalar_mul_base(k: U256): _JacobianPoint =>
    scalar_mul(generator(), k)

  fun scalar_mul(p: Secp256k1PublicKey, k: U256): _JacobianPoint =>
    var acc = _JacobianPoint.infinity_point()
    let base = _JacobianPoint(p.x, p.y, _U256.one())
    var i: USize = 256

    while i > 0 do
      i = i - 1
      acc = _Point.double(acc)
      if _U256.bit(k, i) then
        acc = _Point.add(acc, base)
      end
    end

    acc

  fun to_affine(p: _JacobianPoint): Secp256k1PublicKey ? =>
    if p.infinity then
      error
    end

    let z_inv = _Field.inv(p.z)
    let z2 = _Field.square(z_inv)
    let z3 = _Field.mul(z2, z_inv)
    Secp256k1PublicKey(_Field.mul(p.x, z2), _Field.mul(p.y, z3))

  fun is_on_curve(p: Secp256k1PublicKey): Bool =>
    if _U256.gte(p.x, _Field.p()) or _U256.gte(p.y, _Field.p()) then
      return false
    end

    let y2 = _Field.square(p.y)
    let x3 = _Field.mul(_Field.square(p.x), p.x)
    _U256.eq(y2, _Field.add(x3, _Field.from_u64(7)))
