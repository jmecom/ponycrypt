# ponycrypt

Small Pony SHA-256 and HMAC experiment.

This directory contains from-scratch SHA-256 and generic HMAC implementations in
Pony. It does not import `ssl/crypto`, OpenSSL, libsodium, or another crypto
package.

Library shape:

```pony
let digest = Sha256.digest("abc")
let tag = Hmac[Sha256].digest("key", "message")
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

The Wycheproof test fixture covers HMAC-SHA256 because Wycheproof does not
publish raw SHA-256 digest vectors in `testvectors_v1`. The fixture is generated
from C2SP/wycheproof commit `878e5366008753df2064d40c49f8e2f50f9c6af7`.
