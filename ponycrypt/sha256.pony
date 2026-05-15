use "collections"

primitive Sha256
  """
  Pure Pony SHA-256.

  This is written directly from the FIPS 180-4 algorithm: message padding,
  message schedule expansion, and the 64-round compression function are all
  implemented here without calling an external crypto library.
  """
  fun digest(data: ReadSeq[U8]): Array[U8] val =>
    let d = Sha256Digest
    d.update(data)
    d.final()

  fun hex(data: ReadSeq[U8]): String iso^ =>
    Hex.encode(digest(data))

class Sha256Digest
  embed _buffer: Array[U8]
  var _len: U64 = 0

  var _h0: U32 = 0x6a09e667
  var _h1: U32 = 0xbb67ae85
  var _h2: U32 = 0x3c6ef372
  var _h3: U32 = 0xa54ff53a
  var _h4: U32 = 0x510e527f
  var _h5: U32 = 0x9b05688c
  var _h6: U32 = 0x1f83d9ab
  var _h7: U32 = 0x5be0cd19

  new create() =>
    _buffer = Array[U8](64)

  fun ref update(data: ReadSeq[U8]) =>
    var i: USize = 0
    try
      while i < data.size() do
        _buffer.push(data(i)?)
        _len = _len + 1

        if _buffer.size() == 64 then
          _process_block(_buffer)?
          _buffer.clear()
        end

        i = i + 1
      end
    end

  fun ref final(): Array[U8] val =>
    let bit_len = _len * 8

    try
      _buffer.push(0x80)

      if _buffer.size() > 56 then
        while _buffer.size() < 64 do
          _buffer.push(0)
        end
        _process_block(_buffer)?
        _buffer.clear()
      end

      while _buffer.size() < 56 do
        _buffer.push(0)
      end

      var shift: U64 = 56
      while true do
        _buffer.push(((bit_len >> shift) and 0xff).u8())
        if shift == 0 then break end
        shift = shift - 8
      end

      _process_block(_buffer)?
      _buffer.clear()
    end

    let h0 = _h0
    let h1 = _h1
    let h2 = _h2
    let h3 = _h3
    let h4 = _h4
    let h5 = _h5
    let h6 = _h6
    let h7 = _h7

    recover val
      let out = Array[U8](32)
      _Sha256Bytes.push_u32(out, h0)
      _Sha256Bytes.push_u32(out, h1)
      _Sha256Bytes.push_u32(out, h2)
      _Sha256Bytes.push_u32(out, h3)
      _Sha256Bytes.push_u32(out, h4)
      _Sha256Bytes.push_u32(out, h5)
      _Sha256Bytes.push_u32(out, h6)
      _Sha256Bytes.push_u32(out, h7)
      out
    end

  fun ref _process_block(block: ReadSeq[U8]) ? =>
    let w = Array[U32](64)

    var i: USize = 0
    while i < 16 do
      let j = i * 4
      w.push(
        (block(j)?.u32() << 24) or
        (block(j + 1)?.u32() << 16) or
        (block(j + 2)?.u32() << 8) or
        block(j + 3)?.u32())
      i = i + 1
    end

    while i < 64 do
      w.push(
        _Sha256Words.small_sigma1(w(i - 2)?) +
        w(i - 7)? +
        _Sha256Words.small_sigma0(w(i - 15)?) +
        w(i - 16)?)
      i = i + 1
    end

    var a = _h0
    var b = _h1
    var c = _h2
    var d = _h3
    var e = _h4
    var f = _h5
    var g = _h6
    var h = _h7

    i = 0
    while i < 64 do
      let t1 =
        h +
        _Sha256Words.big_sigma1(e) +
        _Sha256Words.ch(e, f, g) +
        _Sha256Words.k(i)? +
        w(i)?
      let t2 = _Sha256Words.big_sigma0(a) + _Sha256Words.maj(a, b, c)

      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2

      i = i + 1
    end

    _h0 = _h0 + a
    _h1 = _h1 + b
    _h2 = _h2 + c
    _h3 = _h3 + d
    _h4 = _h4 + e
    _h5 = _h5 + f
    _h6 = _h6 + g
    _h7 = _h7 + h

primitive Hex
  fun encode(data: ReadSeq[U8]): String iso^ =>
    let out = recover String(data.size() * 2) end
    let digits = "0123456789abcdef"

    try
      for byte in data.values() do
        out.push(digits((byte >> 4).usize())?)
        out.push(digits((byte and 0x0f).usize())?)
      end
    end

    out

  fun decode(data: ReadSeq[U8]): Array[U8] iso^ ? =>
    if (data.size() % 2) != 0 then
      error
    end

    let out = recover Array[U8](data.size() / 2) end

    var i: USize = 0
    while i < data.size() do
      let hi = _nibble(data(i)?)?
      let lo = _nibble(data(i + 1)?)?
      out.push((hi << 4) or lo)
      i = i + 2
    end

    out

  fun _nibble(c: U8): U8 ? =>
    if (c >= '0') and (c <= '9') then
      c - '0'
    elseif (c >= 'a') and (c <= 'f') then
      (c - 'a') + 10
    elseif (c >= 'A') and (c <= 'F') then
      (c - 'A') + 10
    else
      error
    end

primitive HmacSha256
  fun digest(key: ReadSeq[U8], msg: ReadSeq[U8]): Array[U8] val =>
    let key_block = _key_block(key)
    let inner_pad = Array[U8](64)
    let outer_pad = Array[U8](64)

    try
      for i in Range[USize](0, 64) do
        let b = key_block(i)?
        inner_pad.push(b xor 0x36)
        outer_pad.push(b xor 0x5c)
      end
    end

    let inner = Sha256Digest
    inner.update(inner_pad)
    inner.update(msg)
    let inner_hash = inner.final()

    let outer = Sha256Digest
    outer.update(outer_pad)
    outer.update(inner_hash)
    outer.final()

  fun mac(key: ReadSeq[U8], msg: ReadSeq[U8], tag_size_bits: USize = 256)
    : Array[U8] val ?
  =>
    if (tag_size_bits % 8) != 0 then
      error
    end

    let tag_size = tag_size_bits / 8
    let full = digest(key, msg)

    if tag_size > full.size() then
      error
    end

    recover val
      let out = Array[U8](tag_size)
      var i: USize = 0
      while i < tag_size do
        out.push(full(i)?)
        i = i + 1
      end
      out
    end

  fun verify(key: ReadSeq[U8], msg: ReadSeq[U8], expected: ReadSeq[U8])
    : Bool
  =>
    try
      ConstantTime.eq(mac(key, msg, expected.size() * 8)?, expected)
    else
      false
    end

  fun _key_block(key: ReadSeq[U8]): Array[U8] ref =>
    let out = Array[U8](64)

    if key.size() > 64 then
      _copy(out, Sha256.digest(key))
    else
      _copy(out, key)
    end

    while out.size() < 64 do
      out.push(0)
    end

    out

  fun _copy(out: Array[U8] ref, data: ReadSeq[U8]) =>
    for b in data.values() do
      out.push(b)
    end

primitive ConstantTime
  fun eq(a: ReadSeq[U8], b: ReadSeq[U8]): Bool =>
    var diff: USize = if a.size() == b.size() then 0 else 1 end
    let max = a.size().max(b.size())

    try
      for i in Range[USize](0, max) do
        let av = if i < a.size() then a(i)? else 0 end
        let bv = if i < b.size() then b(i)? else 0 end
        diff = diff or ((av xor bv).usize())
      end
    else
      return false
    end

    diff == 0

primitive _Sha256Bytes
  fun push_u32(out: Array[U8] ref, word: U32) =>
    out.push((word >> 24).u8())
    out.push(((word >> 16) and 0xff).u8())
    out.push(((word >> 8) and 0xff).u8())
    out.push((word and 0xff).u8())

primitive _Sha256Words
  fun rotr(x: U32, n: U32): U32 =>
    (x >> n) or (x << (32 - n))

  fun ch(x: U32, y: U32, z: U32): U32 =>
    (x and y) xor ((x xor 0xffff_ffff) and z)

  fun maj(x: U32, y: U32, z: U32): U32 =>
    (x and y) xor (x and z) xor (y and z)

  fun big_sigma0(x: U32): U32 =>
    rotr(x, 2) xor rotr(x, 13) xor rotr(x, 22)

  fun big_sigma1(x: U32): U32 =>
    rotr(x, 6) xor rotr(x, 11) xor rotr(x, 25)

  fun small_sigma0(x: U32): U32 =>
    rotr(x, 7) xor rotr(x, 18) xor (x >> 3)

  fun small_sigma1(x: U32): U32 =>
    rotr(x, 17) xor rotr(x, 19) xor (x >> 10)

  fun k(i: USize): U32 ? =>
    match i
    | 0 => 0x428a2f98
    | 1 => 0x71374491
    | 2 => 0xb5c0fbcf
    | 3 => 0xe9b5dba5
    | 4 => 0x3956c25b
    | 5 => 0x59f111f1
    | 6 => 0x923f82a4
    | 7 => 0xab1c5ed5
    | 8 => 0xd807aa98
    | 9 => 0x12835b01
    | 10 => 0x243185be
    | 11 => 0x550c7dc3
    | 12 => 0x72be5d74
    | 13 => 0x80deb1fe
    | 14 => 0x9bdc06a7
    | 15 => 0xc19bf174
    | 16 => 0xe49b69c1
    | 17 => 0xefbe4786
    | 18 => 0x0fc19dc6
    | 19 => 0x240ca1cc
    | 20 => 0x2de92c6f
    | 21 => 0x4a7484aa
    | 22 => 0x5cb0a9dc
    | 23 => 0x76f988da
    | 24 => 0x983e5152
    | 25 => 0xa831c66d
    | 26 => 0xb00327c8
    | 27 => 0xbf597fc7
    | 28 => 0xc6e00bf3
    | 29 => 0xd5a79147
    | 30 => 0x06ca6351
    | 31 => 0x14292967
    | 32 => 0x27b70a85
    | 33 => 0x2e1b2138
    | 34 => 0x4d2c6dfc
    | 35 => 0x53380d13
    | 36 => 0x650a7354
    | 37 => 0x766a0abb
    | 38 => 0x81c2c92e
    | 39 => 0x92722c85
    | 40 => 0xa2bfe8a1
    | 41 => 0xa81a664b
    | 42 => 0xc24b8b70
    | 43 => 0xc76c51a3
    | 44 => 0xd192e819
    | 45 => 0xd6990624
    | 46 => 0xf40e3585
    | 47 => 0x106aa070
    | 48 => 0x19a4c116
    | 49 => 0x1e376c08
    | 50 => 0x2748774c
    | 51 => 0x34b0bcb5
    | 52 => 0x391c0cb3
    | 53 => 0x4ed8aa4a
    | 54 => 0x5b9cca4f
    | 55 => 0x682e6ff3
    | 56 => 0x748f82ee
    | 57 => 0x78a5636f
    | 58 => 0x84c87814
    | 59 => 0x8cc70208
    | 60 => 0x90befffa
    | 61 => 0xa4506ceb
    | 62 => 0xbef9a3f7
    | 63 => 0xc67178f2
    else
      error
    end
