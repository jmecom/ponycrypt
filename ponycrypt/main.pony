use "files"

actor Main
  new create(env: Env) =>
    PonyCrypt(env)

primitive PonyCrypt
  fun apply(env: Env) =>
    try
      match env.args.size()
      | 2 =>
        let arg = env.args(1)?
        if (arg == "-h") or (arg == "--help") then
          _usage(env)
        else
          _hash_file(env, arg)
        end
      | 3 =>
        match env.args(1)?
        | "-s" | "--string" =>
          env.out.print(Sha256.hex(env.args(2)?))
        else
          _usage(env)
          env.exitcode(64)
        end
      else
        _usage(env)
        env.exitcode(64)
      end
    else
      env.err.print("ponycrypt: failed to hash input")
      env.exitcode(1)
    end

  fun _hash_file(env: Env, path: String) =>
    let file_path = FilePath(FileAuth(env.root), path)

    match OpenFile(file_path)
    | let file: File =>
      let digest = Sha256Digest

      while true do
        let chunk = file.read(32 * 1024)
        if chunk.size() == 0 then
          break
        end
        digest.update(consume chunk)
      end

      file.dispose()
      let hash = Hex.encode(digest.final())
      env.out.print(Sha256FileLine(consume hash, path))
    else
      env.err.print("ponycrypt: unable to open " + path)
      env.exitcode(1)
    end

  fun _usage(env: Env) =>
    let exe = try env.args(0)? else "ponycrypt" end
    env.out.print("usage:")
    env.out.print("  " + exe + " <file>")
    env.out.print("  " + exe + " --string <text>")

primitive Sha256FileLine
  fun apply(hash: String val, path: String): String iso^ =>
    recover
      let out = String(hash.size() + path.size() + 2)
      out.append(hash)
      out.append("  ")
      out.append(path)
      out
    end
