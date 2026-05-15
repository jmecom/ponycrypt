# ponycrypt

Small Pony SHA-256, HMAC, and AES experiment.

This directory contains from-scratch SHA-256, generic HMAC, and AES block cipher
implementations in Pony. It does not import `ssl/crypto`, OpenSSL, libsodium, or
another crypto package.

AES is implemented without S-box or T-table lookups indexed by secret data. The
S-box is computed with fixed GF(2^8) arithmetic. This is a best-effort
constant-control-flow implementation; Pony and the backend compiler do not
provide a formal constant-time guarantee.

Library shape:

```pony
let digest = Sha256.digest("abc")
let tag = Hmac[Sha256].digest("key", "message")
let ct = Aes.encrypt_block(key, plaintext)?
let pt = Aes.decrypt_block(key, ct)?
```

Build:

```sh
nix develop . --command ponyc ponycrypt -o ponycrypt/build
```

Hash a file:

```sh
./ponycrypt/build/ponycrypt ./ponycrypt/README.md
```

Hash a string:

```sh
./ponycrypt/build/ponycrypt --string abc
```

Known vectors:

```text
SHA256("")  = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Tests:

```sh
nix flake check
```

Or run the Pony test binary directly:

```sh
nix develop . --command ponyc ponycrypt_test -p . -o ponycrypt_test/build
./ponycrypt_test/build/ponycrypt_test
```

The Wycheproof fixtures cover HMAC-SHA256 and AES-CBC-PKCS5. AES-CBC-PKCS5 is
used to exercise AES because Wycheproof does not publish raw AES block vectors
in `testvectors_v1`. The fixtures are generated from C2SP/wycheproof commit
`878e5366008753df2064d40c49f8e2f50f9c6af7`.
