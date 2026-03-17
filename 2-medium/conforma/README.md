# Medium: Conforma

The medium level verifies both the base image and the built image, running the same SLSA provenance checks on each. It then produces a VSA at SLSA Build Level 2, capturing the verification outcome so downstream consumers can enforce policy without re-running the checks.

The policy supports both Tekton Chains and GitHub Actions builds. Two passes are needed because the base image and built image have different signing keys and builder configurations.

## Usage

Pass 1 — Verify the base image (same as mild):

```bash
cosign verify \
  --key 1-mild/conforma/cosign-release.pub \
  --insecure-ignore-tlog \
  <BASE_IMAGE_REF>

ec validate image \
  --image <BASE_IMAGE_REF> \
  --policy 1-mild/conforma/policy.yaml \
  --public-key 1-mild/conforma/cosign-provenance.pub \
  --ignore-rekor
```

Pass 2 — Verify the built image. For Tekton Chains (key-based):

```bash
ec validate image \
  --image <BUILT_IMAGE_REF> \
  --policy 2-medium/conforma/policy.yaml \
  --public-key <CHAINS_PUBLIC_KEY> \
  --ignore-rekor
```

For GitHub Actions (keyless):

```bash
ec validate image \
  --image <BUILT_IMAGE_REF> \
  --policy 2-medium/conforma/policy.yaml \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity '<WORKFLOW_IDENTITY>' \
  --rekor-url https://rekor.sigstore.dev
```

## VSA Generation

The `scripts/generate-vsa.sh` script runs both passes and generates a SLSA VSA. For GitHub Actions (keyless):

```bash
scripts/generate-vsa.sh \
  --image <BUILT_IMAGE_REF> \
  --policy 2-medium/conforma/policy.yaml \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity '<WORKFLOW_IDENTITY>' \
  --rekor-url https://rekor.sigstore.dev \
  --base-image-policy 1-mild/conforma/policy.yaml \
  --base-image-key 1-mild/conforma/cosign-provenance.pub \
  --base-image-release-key 1-mild/conforma/cosign-release.pub \
  --vsa-signing-key vsa.key
```

For Tekton Chains (key-based):

```bash
scripts/generate-vsa.sh \
  --image <BUILT_IMAGE_REF> \
  --policy 2-medium/conforma/policy.yaml \
  --public-key provenance.pub \
  --ignore-rekor \
  --base-image-policy 1-mild/conforma/policy.yaml \
  --base-image-key 1-mild/conforma/cosign-provenance.pub \
  --base-image-release-key 1-mild/conforma/cosign-release.pub \
  --vsa-signing-key vsa.key
```

Use `--no-attach` to produce the VSA predicate without pushing it to the registry.
