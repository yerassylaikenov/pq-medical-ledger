#!/usr/bin/env bash
# Build liboqs 0.12.0 with exactly the schemes used in the paper.
set -euo pipefail
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX="$PWD/oqs" \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024;SIG_sphincs_sha2_128s_simple"
ninja -C liboqs/build install
echo "liboqs installed in $PWD/oqs"
