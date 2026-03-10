#!/usr/bin/env bash
set -euo pipefail

# test_policy.sh - Run OPA tests for mild-to-wild-samples policies
#
# Usage:
#   ./test_policy.sh [mild|medium|wild]
#   ./test_policy.sh              # runs all levels

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMA_POLICY_PATH="${CONFORMA_POLICY_PATH:-${SCRIPT_DIR}/../conforma-policy}"
CONFORMA_CLI_PATH="${CONFORMA_CLI_PATH:-${SCRIPT_DIR}/../conforma-cli}"

if [[ ! -d "${CONFORMA_POLICY_PATH}/policy/lib" ]] || [[ ! -d "${CONFORMA_POLICY_PATH}/policy/release/lib" ]]; then
    echo "Error: conforma-policy not found at ${CONFORMA_POLICY_PATH}"
    echo "Expected policy/lib and policy/release/lib directories"
    echo "Set CONFORMA_POLICY_PATH environment variable or clone it alongside this repo"
    exit 1
fi

# Find ec binary: PATH first, then local build
EC_BIN=""
if command -v ec &> /dev/null; then
    EC_BIN="ec"
elif [[ -x "${CONFORMA_CLI_PATH}/dist/ec" ]]; then
    EC_BIN="${CONFORMA_CLI_PATH}/dist/ec"
else
    echo "Error: 'ec' not found on PATH or at ${CONFORMA_CLI_PATH}/dist/ec"
    echo "Set CONFORMA_CLI_PATH environment variable or add ec to PATH"
    exit 1
fi

run_test() {
    local level=$1
    echo "Testing ${level} policy..."

    local -a paths=(
        "${CONFORMA_POLICY_PATH}/policy/lib"
        "${CONFORMA_POLICY_PATH}/policy/release/lib"
    )

    # Mild includes the github_certificate package for GHA signer identity checks
    if [[ "${level}" == "mild" ]]; then
        paths+=("${CONFORMA_POLICY_PATH}/policy/release/github_certificate")
    fi

    paths+=("${SCRIPT_DIR}/${level}/conforma/")

    "${EC_BIN}" opa test "${paths[@]}" -v
}

if [[ $# -eq 0 ]]; then
    # Run all tests
    for level in mild medium wild; do
        run_test "${level}"
        echo ""
    done
else
    # Run specific level
    level=$1
    if [[ ! "${level}" =~ ^(mild|medium|wild)$ ]]; then
        echo "Error: level must be one of: mild, medium, wild"
        exit 1
    fi
    run_test "${level}"
fi
