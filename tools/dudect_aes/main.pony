use "collections"
use pc = "ponycrypt"

use "path:../../.dudect-build/lib"
use "lib:ponycrypt_dudect"

use @ponycrypt_dudect_run[I32](
  callback: @{(Pointer[U8] tag): U8},
  max_chunks: USize,
  number_measurements: USize,
  chunk_size: USize)

use @ponycrypt_dudect_input_byte[U8](
  data: Pointer[U8] tag,
  index: USize)

actor Main
  new create(env: Env) =>
    let number_measurements =
      try
        env.args(1)?.usize()?
      else
        USize(10000)
      end

    let max_chunks =
      try
        env.args(2)?.usize()?
      else
        USize(50)
      end

    let mode =
      try
        env.args(3)?
      else
        "aes"
      end

    let result =
      if mode == "control" then
        env.out.print(
          "dudect Pony FFI input-copy control: " +
          number_measurements.string() + " measurements/chunk, " +
          max_chunks.string() + " max chunks")
        @ponycrypt_dudect_run(
          addressof InputCopyDudect.do_one_computation,
          max_chunks,
          number_measurements,
          USize(16))
      else
        env.out.print(
          "dudect AES-128 plaintext test: " +
          number_measurements.string() + " measurements/chunk, " +
          max_chunks.string() + " max chunks")
        @ponycrypt_dudect_run(
          addressof AesDudect.do_one_computation,
          max_chunks,
          number_measurements,
          USize(16))
      end

    if result == 0 then
      env.out.print("dudect result: leakage evidence found")
      env.exitcode(1)
    else
      env.out.print("dudect result: no leakage evidence within configured chunks")
    end

primitive AesDudect
  fun @do_one_computation(data: Pointer[U8] tag): U8 =>
    try
      let key = recover val
        let out = Array[U8](16)
        for i in Range[USize](0, 16) do
          out.push(0)
        end
        out
      end

      let block = recover iso Array[U8](16) end
      for i in Range[USize](0, 16) do
        block.push(@ponycrypt_dudect_input_byte(data, i))
      end
      let block_val: Array[U8] val = consume block

      let encrypted = pc.Aes.encrypt_block(key, block_val)?
      encrypted(0)?
    else
      0
    end

primitive InputCopyDudect
  fun @do_one_computation(data: Pointer[U8] tag): U8 =>
    try
      let block = recover iso Array[U8](16) end
      for i in Range[USize](0, 16) do
        block.push(@ponycrypt_dudect_input_byte(data, i))
      end
      let block_val: Array[U8] val = consume block
      block_val(0)?
    else
      0
    end
