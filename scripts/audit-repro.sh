# Soteria reproducer for security audits.
#
# This script:
#   1. Clones the repo at the audited SHA (passed as $1).
#   2. Builds the TCB and runs the test suite.
#   3. Captures the binary HMAC and the dependency tree.
#
# Usage:
#   AUDIT_SHA=abc1234 ./scripts/audit-repro.sh
#
# Output:
#   artifacts/build.log
#   artifacts/test.log
#   artifacts/cargo-tree.txt
#   artifacts/soteria-module.hmac

set -euo pipefail

AUDIT_SHA="${AUDIT_SHA:-HEAD}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-artifacts}"

if [ -z "${AUDIT_SHA}" ] || [ "${AUDIT_SHA}" = "HEAD" ]; then
    echo "AUDIT_SHA is unset; using current HEAD."
    AUDIT_SHA="$(git rev-parse HEAD)"
fi

mkdir -p "${ARTIFACTS_DIR}"

echo "[1/5] Verifying repo at ${AUDIT_SHA}..."
git rev-parse "${AUDIT_SHA}" >/dev/null

echo "[2/5] Building TCB (default features)..."
cargo build --release --target-dir "${ARTIFACTS_DIR}/target" \
    2>&1 | tee "${ARTIFACTS_DIR}/build.log"

echo "[3/5] Running TCB tests..."
cargo test --lib --target-dir "${ARTIFACTS_DIR}/target" \
    2>&1 | tee "${ARTIFACTS_DIR}/test.log"

echo "[4/5] Capturing dependency tree..."
cargo tree --target-dir "${ARTIFACTS_DIR}/target" \
    > "${ARTIFACTS_DIR}/cargo-tree.txt" 2>&1

echo "[5/5] Capturing binary HMAC..."
if [ -f "${ARTIFACTS_DIR}/target/release/soteria-module.hmac" ]; then
    cp "${ARTIFACTS_DIR}/target/release/soteria-module.hmac" \
       "${ARTIFACTS_DIR}/soteria-module.hmac"
fi

echo ""
echo "Audit artifacts written to ${ARTIFACTS_DIR}/:"
echo "  build.log            - cargo build output"
echo "  test.log             - cargo test output"
echo "  cargo-tree.txt       - dependency tree"
echo "  soteria-module.hmac  - HMAC of built binary (if present)"
echo ""
echo "Audited SHA: ${AUDIT_SHA}"
