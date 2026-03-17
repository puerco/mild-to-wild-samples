#!/usr/bin/env bash
# generate-vsa.sh — Verify an image and its base image, then generate a
# SLSA Verification Summary Attestation (https://slsa.dev/verification_summary/v1).
#
# Extracts the base image from OCI manifest annotations, runs Conforma
# policy validation on the built image (and optionally the base image),
# determines the SLSA Build Level, and produces a signed VSA.
#
# Usage:
#   generate-vsa.sh \
#     --image IMAGE_REF \
#     --policy POLICY_PATH \
#     --vsa-signing-key KEY_PATH \
#     [--public-key KEY]                # built image provenance key (key-based)
#     [--certificate-identity ID]       # built image workflow identity (keyless)
#     [--certificate-oidc-issuer URL]   # OIDC issuer (keyless)
#     [--rekor-url URL]                 # Rekor URL (keyless, default: skip)
#     [--ignore-rekor]                  # skip Rekor for built image
#     [--base-image-policy POLICY]      # base image policy (default: 1-mild/conforma/policy.yaml)
#     [--base-image-key KEY]            # base image provenance key
#     [--base-image-release-key KEY]    # base image release signature key (cosign verify)
#     [--skip-base-image]               # skip base image verification
#     [--report FILE]                   # reuse existing report (skip built image validation)
#     [--output FILE]                   # write predicate JSON here
#     [--no-attach]                     # skip cosign attest (just produce predicate)
#     [--tlog-upload]                   # upload attestation to Rekor (default: skip)
#     [--extra-ec-args ARGS]            # additional args for ec validate
#
# Requires: jq, ec, cosign, and one of: crane, skopeo

set -euo pipefail

# Find ec binary
EC_BIN="${EC_BIN:-}"
if [[ -z "$EC_BIN" ]]; then
  if command -v ec &>/dev/null; then
    EC_BIN="ec"
  else
    echo "Error: 'ec' not found on PATH. Set EC_BIN to the ec binary path." >&2
    exit 1
  fi
fi

IMAGE=""
POLICY=""
VSA_SIGNING_KEY=""
PUBLIC_KEY=""
CERT_IDENTITY=""
CERT_OIDC_ISSUER=""
REKOR_URL=""
IGNORE_REKOR=false
BASE_IMAGE_POLICY=""
BASE_IMAGE_KEY=""
BASE_IMAGE_RELEASE_KEY=""
SKIP_BASE_IMAGE=false
REPORT=""
OUTPUT=""
NO_ATTACH=false
TLOG_UPLOAD=false
EXTRA_EC_ARGS=""

usage() {
  sed -n '2,/^$/s/^# //p' "$0"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)                  IMAGE="$2"; shift 2 ;;
    --policy)                 POLICY="$2"; shift 2 ;;
    --vsa-signing-key)        VSA_SIGNING_KEY="$2"; shift 2 ;;
    --public-key)             PUBLIC_KEY="$2"; shift 2 ;;
    --certificate-identity)   CERT_IDENTITY="$2"; shift 2 ;;
    --certificate-oidc-issuer) CERT_OIDC_ISSUER="$2"; shift 2 ;;
    --rekor-url)              REKOR_URL="$2"; shift 2 ;;
    --ignore-rekor)           IGNORE_REKOR=true; shift ;;
    --base-image-policy)      BASE_IMAGE_POLICY="$2"; shift 2 ;;
    --base-image-key)         BASE_IMAGE_KEY="$2"; shift 2 ;;
    --base-image-release-key) BASE_IMAGE_RELEASE_KEY="$2"; shift 2 ;;
    --skip-base-image)        SKIP_BASE_IMAGE=true; shift ;;
    --report)                 REPORT="$2"; shift 2 ;;
    --output)                 OUTPUT="$2"; shift 2 ;;
    --no-attach)              NO_ATTACH=true; shift ;;
    --tlog-upload)            TLOG_UPLOAD=true; shift ;;
    --extra-ec-args)          EXTRA_EC_ARGS="$2"; shift 2 ;;
    -h|--help)                usage ;;
    *)                        echo "Unknown option: $1" >&2; usage ;;
  esac
done

for var in IMAGE POLICY; do
  if [[ -z "${!var}" ]]; then
    echo "Error: --$(echo "$var" | tr '[:upper:]' '[:lower:]') is required" >&2
    usage
  fi
done

if [[ "$NO_ATTACH" == false && -z "$VSA_SIGNING_KEY" ]]; then
  echo "Error: --vsa-signing-key is required unless --no-attach is set" >&2
  usage
fi

# --- Helpers ---

resolve_digest() {
  local img="$1"
  if [[ "$img" == *@sha256:* ]]; then
    echo "${img##*@}"
    return
  fi
  if command -v crane &>/dev/null; then
    crane digest "$img"
  elif command -v skopeo &>/dev/null; then
    skopeo inspect --format '{{.Digest}}' "docker://${img}"
  else
    echo "Error: need crane or skopeo to resolve digest" >&2
    exit 1
  fi
}

get_manifest_json() {
  local img="$1"
  if command -v crane &>/dev/null; then
    crane manifest "$img"
  elif command -v skopeo &>/dev/null; then
    skopeo inspect --raw "docker://${img}"
  else
    echo "Error: need crane or skopeo to inspect manifest" >&2
    exit 1
  fi
}

determine_level() {
  local report="$1" component_selector="$2"
  jq -r "
    ${component_selector} |
    if (
      ([(.successes // [])[] | select(.metadata.code == \"wild.all_tasks_trusted\")] | length > 0) and
      ([(.warnings // [])[]  | select(.metadata.code == \"wild.all_tasks_trusted\" or .metadata.code == \"wild.pipelinerun_provenance_for_trusted_tasks\")] | length == 0)
    )
    then \"SLSA_BUILD_LEVEL_3\"
    else \"SLSA_BUILD_LEVEL_2\"
    end
  " "$report"
}

# --- Resolve image ---

IMAGE_DIGEST=$(resolve_digest "$IMAGE")
IMAGE_REPO="${IMAGE%%@*}"
IMAGE_REPO="${IMAGE_REPO%%:*}"
IMAGE_REF="${IMAGE_REPO}@${IMAGE_DIGEST}"

echo "=== Verifying $IMAGE_REF ==="

# --- Extract base image from OCI manifest annotations ---

MANIFEST=$(get_manifest_json "$IMAGE_REF")
BASE_NAME=$(echo "$MANIFEST" | jq -r '.annotations["org.opencontainers.image.base.name"] // empty')
BASE_DIGEST=$(echo "$MANIFEST" | jq -r '.annotations["org.opencontainers.image.base.digest"] // empty')

# --- Pass 1: Verify base image ---

BASE_LEVEL="SLSA_BUILD_LEVEL_2"
if [[ "$SKIP_BASE_IMAGE" == true ]]; then
  echo "--- Skipping base image verification"
elif [[ -z "$BASE_NAME" || -z "$BASE_DIGEST" ]]; then
  echo "--- No base image found in manifest annotations"
else
  BASE_REF="${BASE_NAME%%:*}@${BASE_DIGEST}"
  echo "--- Pass 1: Verifying base image ${BASE_REF}"

  # Step 1a: Verify release signature (if key provided)
  if [[ -n "$BASE_IMAGE_RELEASE_KEY" ]]; then
    echo "  Verifying release signature..."
    cosign verify \
      --key "$BASE_IMAGE_RELEASE_KEY" \
      --insecure-ignore-tlog \
      "$BASE_REF" > /dev/null 2>&1
    echo "  Release signature: OK"
  fi

  # Step 1b: Verify provenance (if policy and key provided)
  if [[ -n "$BASE_IMAGE_POLICY" && -n "$BASE_IMAGE_KEY" ]]; then
    echo "  Verifying provenance..."
    "$EC_BIN" validate image \
      --image "$BASE_REF" \
      --policy "$BASE_IMAGE_POLICY" \
      --public-key "$BASE_IMAGE_KEY" \
      --ignore-rekor \
      --output "json=/tmp/vsa-base-report.json" 2>/dev/null

    BASE_RESULT=$(jq -r '
      if (.components // [] | length) == 0 then "FAILED"
      elif [.components[] | select((.violations // .failures // []) | length > 0)] | length > 0 then "FAILED"
      else "PASSED"
      end
    ' /tmp/vsa-base-report.json)

    if [[ "$BASE_RESULT" != "PASSED" ]]; then
      echo "  Base image provenance verification FAILED" >&2
      jq '.components[] | .violations // .failures // []' /tmp/vsa-base-report.json >&2
      exit 1
    fi
    echo "  Provenance: OK"
  else
    echo "  Skipping provenance check (no base image policy/key provided)"
  fi
fi

# --- Pass 2: Verify built image ---

if [[ -n "$REPORT" && -f "$REPORT" ]]; then
  echo "--- Using existing report: $REPORT"
else
  echo "--- Pass 2: Verifying built image"
  REPORT=$(mktemp /tmp/vsa-report.XXXXXX.json)

  EC_ARGS=(
    validate image
    --image "$IMAGE_REF"
    --policy "$POLICY"
    --show-successes
    --output "json=${REPORT}"
  )

  if [[ -n "$PUBLIC_KEY" ]]; then
    EC_ARGS+=(--public-key "$PUBLIC_KEY")
  fi
  if [[ -n "$CERT_IDENTITY" ]]; then
    EC_ARGS+=(--certificate-identity "$CERT_IDENTITY")
  fi
  if [[ -n "$CERT_OIDC_ISSUER" ]]; then
    EC_ARGS+=(--certificate-oidc-issuer "$CERT_OIDC_ISSUER")
  fi
  if [[ -n "$REKOR_URL" ]]; then
    EC_ARGS+=(--rekor-url "$REKOR_URL")
  fi
  if [[ "$IGNORE_REKOR" == true ]]; then
    EC_ARGS+=(--ignore-rekor)
  fi
  # shellcheck disable=SC2086
  if [[ -n "$EXTRA_EC_ARGS" ]]; then
    EC_ARGS+=($EXTRA_EC_ARGS)
  fi

  "$EC_BIN" "${EC_ARGS[@]}" 2>/dev/null
fi

# --- Check result ---

RESULT=$(jq -r '
  if (.components // [] | length) == 0 then "FAILED"
  elif [.components[] | select((.violations // .failures // []) | length > 0)] | length > 0 then "FAILED"
  else "PASSED"
  end
' "$REPORT")

if [[ "$RESULT" != "PASSED" ]]; then
  echo "Error: policy evaluation did not pass, cannot generate VSA" >&2
  jq '.components[] | .violations // .failures // []' "$REPORT" >&2
  exit 1
fi

echo "  Policy evaluation: PASSED"

# --- Determine levels ---

BUILT_LEVEL=$(determine_level "$REPORT" '([.components[] | select(.name == "built-image")] | first) // (.components | first)')
echo "  Built image level: $BUILT_LEVEL"

DEPS='{}'
if [[ -n "$BASE_NAME" && -n "$BASE_DIGEST" && "$SKIP_BASE_IMAGE" != true ]]; then
  BASE_REF="${BASE_NAME%%:*}@${BASE_DIGEST}"
  DEPS=$(jq -n --arg level "$BASE_LEVEL" '{($level): 1}')
  echo "  Base image: ${BASE_REF} -> $BASE_LEVEL"
fi

# --- Generate VSA predicate ---

EC_VERSION=$(jq -r '."ec-version" // "unknown"' "$REPORT")
TIME_VERIFIED=$(jq -r '."effective-time" // empty' "$REPORT")
if [[ -z "$TIME_VERIFIED" ]]; then
  TIME_VERIFIED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
fi

PREDICATE=$(jq -n \
  --arg verifier_id "https://conforma.dev/cli" \
  --arg ec_version "$EC_VERSION" \
  --arg time_verified "$TIME_VERIFIED" \
  --arg resource_uri "$IMAGE_REF" \
  --arg policy_uri "$POLICY" \
  --arg level "$BUILT_LEVEL" \
  --argjson deps "$DEPS" \
  '{
    verifier: {
      id: $verifier_id,
      version: { ec: $ec_version }
    },
    timeVerified: $time_verified,
    resourceUri: $resource_uri,
    policy: { uri: $policy_uri },
    verificationResult: "PASSED",
    verifiedLevels: [$level],
    dependencyLevels: (if ($deps | keys | length) > 0 then $deps else null end),
    slsaVersion: "1.0"
  }')

PREDICATE_FILE="${OUTPUT:-$(mktemp /tmp/vsa-predicate.XXXXXX.json)}"
echo "$PREDICATE" > "$PREDICATE_FILE"

echo ""
echo "=== VSA predicate ==="
jq . "$PREDICATE_FILE"

# --- Attach VSA to image ---

if [[ "$NO_ATTACH" == true ]]; then
  echo "Predicate written to $PREDICATE_FILE (not attached)"
  exit 0
fi

COSIGN_ARGS=(
  attest
  --key "$VSA_SIGNING_KEY"
  --type https://slsa.dev/verification_summary/v1
  --predicate "$PREDICATE_FILE"
)

if [[ "$TLOG_UPLOAD" == false ]]; then
  COSIGN_ARGS+=(--tlog-upload=false)
fi

COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign "${COSIGN_ARGS[@]}" "$IMAGE_REF"
echo "VSA attached to $IMAGE_REF"
