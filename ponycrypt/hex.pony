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
