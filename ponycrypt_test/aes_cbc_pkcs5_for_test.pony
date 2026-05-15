use "collections"
use pc = "ponycrypt"

primitive AesCbcPkcs5ForTest
  fun encrypt(key: ReadSeq[U8], iv: ReadSeq[U8], msg: ReadSeq[U8])
    : Array[U8] val ?
  =>
    if iv.size() != 16 then
      error
    end

    let padded = _pad(msg)
    let prev = _copy_block(iv)?
    let out = recover iso Array[U8](padded.size()) end

    var offset: USize = 0
    while offset < padded.size() do
      let block = Array[U8](16)
      for i in Range[USize](0, 16) do
        block.push(padded(offset + i)? xor prev(i)?)
      end

      let encrypted = pc.Aes.encrypt_block(key, block)?
      for i in Range[USize](0, 16) do
        let b = encrypted(i)?
        out.push(b)
        prev.update(i, b)?
      end

      offset = offset + 16
    end

    consume out

  fun decrypt(key: ReadSeq[U8], iv: ReadSeq[U8], ct: ReadSeq[U8])
    : Array[U8] val ?
  =>
    if (iv.size() != 16) or (ct.size() == 0) or ((ct.size() % 16) != 0) then
      error
    end

    let prev = _copy_block(iv)?
    let padded = Array[U8](ct.size())

    var offset: USize = 0
    while offset < ct.size() do
      let block = _copy_block_at(ct, offset)?
      let decrypted = pc.Aes.decrypt_block(key, block)?

      for i in Range[USize](0, 16) do
        padded.push(decrypted(i)? xor prev(i)?)
        prev.update(i, block(i)?)?
      end

      offset = offset + 16
    end

    _unpad(padded)?

  fun _pad(msg: ReadSeq[U8]): Array[U8] ref =>
    let pad_len = 16 - (msg.size() % 16)
    let out = Array[U8](msg.size() + pad_len)

    for b in msg.values() do
      out.push(b)
    end

    for i in Range[USize](0, pad_len) do
      out.push(pad_len.u8())
    end

    out

  fun _unpad(data: ReadSeq[U8]): Array[U8] val ? =>
    if data.size() == 0 then
      error
    end

    let pad_len = data(data.size() - 1)?.usize()
    if (pad_len == 0) or (pad_len > 16) or (pad_len > data.size()) then
      error
    end

    var i = data.size() - pad_len
    while i < data.size() do
      if data(i)? != pad_len.u8() then
        error
      end
      i = i + 1
    end

    let out = recover iso Array[U8](data.size() - pad_len) end
    i = 0
    while i < (data.size() - pad_len) do
      out.push(data(i)?)
      i = i + 1
    end
    consume out

  fun _copy_block(data: ReadSeq[U8]): Array[U8] ref ? =>
    if data.size() != 16 then
      error
    end

    _copy_block_at(data, 0)?

  fun _copy_block_at(data: ReadSeq[U8], offset: USize): Array[U8] ref ? =>
    let out = Array[U8](16)
    for i in Range[USize](0, 16) do
      out.push(data(offset + i)?)
    end
    out
