#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dudect_commit="dc269651fb2567e46755cfb2a13d3875592968b5"
build_dir="${repo_root}/.dudect-build"
dudect_dir="${build_dir}/dudect"
lib_dir="${build_dir}/lib"
bin_dir="${build_dir}/bin"

measurements="${1:-10000}"
max_chunks="${2:-50}"
mode="${3:-scalar-mul-base}"

cd "${repo_root}"

mkdir -p "${build_dir}" "${lib_dir}" "${bin_dir}"

if [[ ! -d "${dudect_dir}/.git" ]]; then
  git clone https://github.com/oreparaz/dudect.git "${dudect_dir}"
fi

git -C "${dudect_dir}" fetch --quiet origin "${dudect_commit}"
git -C "${dudect_dir}" checkout --quiet "${dudect_commit}"

/usr/bin/cc \
  -arch x86_64 \
  -std=c11 \
  -O2 \
  -mmacosx-version-min=13.0 \
  -I"${dudect_dir}/src" \
  -c "${repo_root}/tools/dudect_aes/ponycrypt_dudect_adapter.c" \
  -o "${build_dir}/ponycrypt_dudect_adapter.o"

/usr/bin/ar rcs \
  "${lib_dir}/libponycrypt_dudect.a" \
  "${build_dir}/ponycrypt_dudect_adapter.o"

nix --extra-experimental-features 'nix-command flakes' develop \
  --system x86_64-darwin \
  "${repo_root}" \
  --command ponyc \
  "${repo_root}/tools/dudect_secp256k1" \
  -p "${repo_root}" \
  -o "${bin_dir}" \
  --cpu x86-64

"${bin_dir}/dudect_secp256k1" \
  "${measurements}" \
  "${max_chunks}" \
  "${mode}"
