use "collections"

primitive Aes
  """
  AES block encryption and decryption for 128-, 192-, and 256-bit keys.

  This avoids secret-indexed lookup tables. The S-box is computed from fixed
  GF(2^8) arithmetic so the AES core has no secret-dependent branches or
  secret-dependent memory indexes.
  """
  fun encrypt_block(key: ReadSeq[U8], block: ReadSeq[U8])
    : Array[U8] val ?
  =>
    if block.size() != 16 then
      error
    end

    let nr = _rounds(key.size())?
    let round_keys = _expand_key(key)?
    let state = _copy_block(block)?

    _add_round_key(state, round_keys, 0)?

    var round: USize = 1
    while round < nr do
      _sub_bytes(state)?
      _shift_rows(state)?
      _mix_columns(state)?
      _add_round_key(state, round_keys, round)?
      round = round + 1
    end

    _sub_bytes(state)?
    _shift_rows(state)?
    _add_round_key(state, round_keys, nr)?

    _freeze(state)

  fun decrypt_block(key: ReadSeq[U8], block: ReadSeq[U8])
    : Array[U8] val ?
  =>
    if block.size() != 16 then
      error
    end

    let nr = _rounds(key.size())?
    let round_keys = _expand_key(key)?
    let state = _copy_block(block)?

    _add_round_key(state, round_keys, nr)?

    var round = nr - 1
    while round > 0 do
      _inv_shift_rows(state)?
      _inv_sub_bytes(state)?
      _add_round_key(state, round_keys, round)?
      _inv_mix_columns(state)?
      round = round - 1
    end

    _inv_shift_rows(state)?
    _inv_sub_bytes(state)?
    _add_round_key(state, round_keys, 0)?

    _freeze(state)

  fun _rounds(key_size: USize): USize ? =>
    match key_size
    | 16 => 10
    | 24 => 12
    | 32 => 14
    else
      error
    end

  fun _copy_block(block: ReadSeq[U8]): Array[U8] ref ? =>
    let out = Array[U8](16)
    for i in Range[USize](0, 16) do
      out.push(block(i)?)
    end
    out

  fun _freeze(data: ReadSeq[U8]): Array[U8] val =>
    let out = recover iso Array[U8](data.size()) end
    for b in data.values() do
      out.push(b)
    end
    consume out

  fun _expand_key(key: ReadSeq[U8]): Array[U32] ref ? =>
    let nr = _rounds(key.size())?
    let nk = key.size() / 4
    let total_words = 4 * (nr + 1)
    let words = Array[U32](total_words)

    var i: USize = 0
    while i < nk do
      let j = i * 4
      words.push(
        (key(j)?.u32() << 24) or
        (key(j + 1)?.u32() << 16) or
        (key(j + 2)?.u32() << 8) or
        key(j + 3)?.u32())
      i = i + 1
    end

    var rcon: U8 = 1
    while i < total_words do
      var temp = words(i - 1)?

      if (i % nk) == 0 then
        temp = _sub_word(_rot_word(temp)) xor (rcon.u32() << 24)
        rcon = _xtime(rcon)
      elseif (nk > 6) and ((i % nk) == 4) then
        temp = _sub_word(temp)
      end

      words.push(words(i - nk)? xor temp)
      i = i + 1
    end

    words

  fun _add_round_key(
    state: Array[U8] ref,
    round_keys: Array[U32] ref,
    round: USize)
    ?
  =>
    let offset = round * 4
    for col in Range[USize](0, 4) do
      let word = round_keys(offset + col)?
      let base = col * 4
      state.update(base, state(base)? xor (word >> 24).u8())?
      state.update(base + 1, state(base + 1)? xor ((word >> 16) and 0xff).u8())?
      state.update(base + 2, state(base + 2)? xor ((word >> 8) and 0xff).u8())?
      state.update(base + 3, state(base + 3)? xor (word and 0xff).u8())?
    end

  fun _sub_bytes(state: Array[U8] ref) ? =>
    for i in Range[USize](0, 16) do
      state.update(i, _sub_byte(state(i)?))?
    end

  fun _inv_sub_bytes(state: Array[U8] ref) ? =>
    for i in Range[USize](0, 16) do
      state.update(i, _inv_sub_byte(state(i)?))?
    end

  fun _shift_rows(state: Array[U8] ref) ? =>
    var t = state(1)?
    state.update(1, state(5)?)?
    state.update(5, state(9)?)?
    state.update(9, state(13)?)?
    state.update(13, t)?

    t = state(2)?
    state.update(2, state(10)?)?
    state.update(10, t)?
    t = state(6)?
    state.update(6, state(14)?)?
    state.update(14, t)?

    t = state(15)?
    state.update(15, state(11)?)?
    state.update(11, state(7)?)?
    state.update(7, state(3)?)?
    state.update(3, t)?

  fun _inv_shift_rows(state: Array[U8] ref) ? =>
    var t = state(13)?
    state.update(13, state(9)?)?
    state.update(9, state(5)?)?
    state.update(5, state(1)?)?
    state.update(1, t)?

    t = state(2)?
    state.update(2, state(10)?)?
    state.update(10, t)?
    t = state(6)?
    state.update(6, state(14)?)?
    state.update(14, t)?

    t = state(3)?
    state.update(3, state(7)?)?
    state.update(7, state(11)?)?
    state.update(11, state(15)?)?
    state.update(15, t)?

  fun _mix_columns(state: Array[U8] ref) ? =>
    for col in Range[USize](0, 4) do
      let i = col * 4
      let a0 = state(i)?
      let a1 = state(i + 1)?
      let a2 = state(i + 2)?
      let a3 = state(i + 3)?

      state.update(i, _mul2(a0) xor _mul3(a1) xor a2 xor a3)?
      state.update(i + 1, a0 xor _mul2(a1) xor _mul3(a2) xor a3)?
      state.update(i + 2, a0 xor a1 xor _mul2(a2) xor _mul3(a3))?
      state.update(i + 3, _mul3(a0) xor a1 xor a2 xor _mul2(a3))?
    end

  fun _inv_mix_columns(state: Array[U8] ref) ? =>
    for col in Range[USize](0, 4) do
      let i = col * 4
      let a0 = state(i)?
      let a1 = state(i + 1)?
      let a2 = state(i + 2)?
      let a3 = state(i + 3)?

      state.update(i,
        _gf_mul(a0, 0x0e) xor _gf_mul(a1, 0x0b) xor
        _gf_mul(a2, 0x0d) xor _gf_mul(a3, 0x09))?
      state.update(i + 1,
        _gf_mul(a0, 0x09) xor _gf_mul(a1, 0x0e) xor
        _gf_mul(a2, 0x0b) xor _gf_mul(a3, 0x0d))?
      state.update(i + 2,
        _gf_mul(a0, 0x0d) xor _gf_mul(a1, 0x09) xor
        _gf_mul(a2, 0x0e) xor _gf_mul(a3, 0x0b))?
      state.update(i + 3,
        _gf_mul(a0, 0x0b) xor _gf_mul(a1, 0x0d) xor
        _gf_mul(a2, 0x09) xor _gf_mul(a3, 0x0e))?
    end

  fun _sub_word(word: U32): U32 =>
    (_sub_byte((word >> 24).u8()).u32() << 24) or
    (_sub_byte(((word >> 16) and 0xff).u8()).u32() << 16) or
    (_sub_byte(((word >> 8) and 0xff).u8()).u32() << 8) or
    _sub_byte((word and 0xff).u8()).u32()

  fun _rot_word(word: U32): U32 =>
    (word << 8) or (word >> 24)

  fun _sub_byte(x: U8): U8 =>
    let y = _gf_inv(x)
    y xor _rotl8(y, 1) xor _rotl8(y, 2) xor _rotl8(y, 3) xor
      _rotl8(y, 4) xor 0x63

  fun _inv_sub_byte(x: U8): U8 =>
    _gf_inv(_rotl8(x, 1) xor _rotl8(x, 3) xor _rotl8(x, 6) xor 0x05)

  fun _gf_inv(x: U8): U8 =>
    var result: U8 = 1
    var base = x
    var exp: U16 = 254

    while exp > 0 do
      if (exp and 1) == 1 then
        result = _gf_mul(result, base)
      end
      base = _gf_mul(base, base)
      exp = exp >> 1
    end

    result

  fun _gf_mul(a': U8, b': U8): U8 =>
    var a = a'
    var b = b'
    var out: U8 = 0

    for i in Range[USize](0, 8) do
      let mask = (b and 1) * 0xff
      out = out xor (a and mask)
      a = _xtime(a)
      b = b >> 1
    end

    out

  fun _mul2(x: U8): U8 =>
    _xtime(x)

  fun _mul3(x: U8): U8 =>
    _xtime(x) xor x

  fun _xtime(x: U8): U8 =>
    (x << 1) xor (((x >> 7) and 1) * 0x1b)

  fun _rotl8(x: U8, n: U8): U8 =>
    (x << n) or (x >> (8 - n))
