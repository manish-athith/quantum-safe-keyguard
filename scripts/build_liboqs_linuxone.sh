#!/usr/bin/env bash
set -euo pipefail

LIBOQS_TAG="0.16.0"
LIBOQS_COMMIT="5a1a854b0dc9f2141bdc771c555ee60c37950183"
VENDOR_DIR="${HOME}/vendor/liboqs"
INSTALL_PREFIX="${HOME}/.local"

mkdir -p "${HOME}/vendor"

if [[ ! -d "${VENDOR_DIR}/.git" ]]; then
  git clone --depth 1 --branch "${LIBOQS_TAG}" \
    https://github.com/open-quantum-safe/liboqs.git "${VENDOR_DIR}"
fi

actual_commit="$(git -C "${VENDOR_DIR}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${LIBOQS_COMMIT}" ]]; then
  echo "Unexpected liboqs commit: ${actual_commit}" >&2
  exit 1
fi

cmake -S "${VENDOR_DIR}" -B "${VENDOR_DIR}/build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}"

cmake --build "${VENDOR_DIR}/build" --parallel 3
"${VENDOR_DIR}/build/tests/test_kem" ML-KEM-768
"${VENDOR_DIR}/build/tests/test_sig" ML-DSA-65
cmake --install "${VENDOR_DIR}/build"

echo "liboqs ${LIBOQS_TAG} installed under ${INSTALL_PREFIX}"

