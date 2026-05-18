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
        "scalar-mul-base"
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
          USize(32))
      else
        env.out.print(
          "dudect secp256k1 scalar_mul_base scalar test: " +
          number_measurements.string() + " measurements/chunk, " +
          max_chunks.string() + " max chunks")
        @ponycrypt_dudect_run(
          addressof Secp256k1ScalarMulBaseDudect.do_one_computation,
          max_chunks,
          number_measurements,
          USize(32))
      end

    if result == 0 then
      env.out.print("dudect result: leakage evidence found")
      env.exitcode(1)
    else
      env.out.print("dudect result: no leakage evidence within configured chunks")
    end

primitive Secp256k1ScalarMulBaseDudect
  fun @do_one_computation(data: Pointer[U8] tag): U8 =>
    try
      let scalar_bytes = recover iso Array[U8](32) end
      for i in Range[USize](0, 32) do
        scalar_bytes.push(@ponycrypt_dudect_input_byte(data, i))
      end
      let scalar_bytes_val: Array[U8] val = consume scalar_bytes
      let scalar = pc.Secp256k1MathForTest.u256_from_bytes(scalar_bytes_val)?

      let public_key = pc.Secp256k1MathForTest.scalar_mul_base(scalar)?
      public_key.to_uncompressed()(1)?
    else
      0
    end

primitive InputCopyDudect
  fun @do_one_computation(data: Pointer[U8] tag): U8 =>
    try
      let block = recover iso Array[U8](32) end
      for i in Range[USize](0, 32) do
        block.push(@ponycrypt_dudect_input_byte(data, i))
      end
      let block_val: Array[U8] val = consume block
      block_val(0)?
    else
      0
    end
