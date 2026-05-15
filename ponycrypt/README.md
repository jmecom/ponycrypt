# ponycrypt

Small Pony SHA-256 experiment.

This directory contains a from-scratch SHA-256 implementation in Pony. It does
not import `ssl/crypto`, OpenSSL, libsodium, or another crypto package.

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
