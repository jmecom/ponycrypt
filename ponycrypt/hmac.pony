use "collections"

interface val HashAlgorithm
  new val create()
  fun digest(data: ReadSeq[U8]): Array[U8] val
  fun block_size(): USize
  fun output_size(): USize

primitive Hmac[H: HashAlgorithm val]
  fun digest(key: ReadSeq[U8], msg: ReadSeq[U8]): Array[U8] val =>
    let block_size = H.block_size()
    let key_block = _key_block(key, block_size)
    let inner_pad = Array[U8](block_size)
    let outer_pad = Array[U8](block_size)

    try
      for i in Range[USize](0, block_size) do
        let b = key_block(i)?
        inner_pad.push(b xor 0x36)
        outer_pad.push(b xor 0x5c)
      end
    end

    let inner_msg = Array[U8](block_size + msg.size())
    _copy(inner_msg, inner_pad)
    _copy(inner_msg, msg)
    let inner_hash = H.digest(inner_msg)

    let outer_msg = Array[U8](block_size + inner_hash.size())
    _copy(outer_msg, outer_pad)
    _copy(outer_msg, inner_hash)
    H.digest(outer_msg)

  fun mac(key: ReadSeq[U8], msg: ReadSeq[U8], tag_size_bits: USize = 0)
    : Array[U8] val ?
  =>
    let requested_bits =
      if tag_size_bits == 0 then
        H.output_size() * 8
      else
        tag_size_bits
      end

    if (requested_bits % 8) != 0 then
      error
    end

    let tag_size = requested_bits / 8
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

  fun _key_block(key: ReadSeq[U8], block_size: USize): Array[U8] ref =>
    let out = Array[U8](block_size)

    if key.size() > block_size then
      _copy(out, H.digest(key))
    else
      _copy(out, key)
    end

    while out.size() < block_size do
      out.push(0)
    end

    out

  fun _copy(out: Array[U8] ref, data: ReadSeq[U8]) =>
    for b in data.values() do
      out.push(b)
    end

primitive HmacSha256
  fun digest(key: ReadSeq[U8], msg: ReadSeq[U8]): Array[U8] val =>
    Hmac[Sha256].digest(key, msg)

  fun mac(key: ReadSeq[U8], msg: ReadSeq[U8], tag_size_bits: USize = 256)
    : Array[U8] val ?
  =>
    Hmac[Sha256].mac(key, msg, tag_size_bits)?

  fun verify(key: ReadSeq[U8], msg: ReadSeq[U8], expected: ReadSeq[U8])
    : Bool
  =>
    Hmac[Sha256].verify(key, msg, expected)

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
