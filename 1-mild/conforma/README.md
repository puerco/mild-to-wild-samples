# Mild: Conforma

Verifies the base image (e.g. UBI) used in the Containerfile. Two custom rules check that SLSA provenance is present and that the buildType matches an allowlist. The remaining checks — builder identity, source materials, and external parameters — come from the upstream Conforma policy library (`slsa_build_build_service`, `slsa_source_version_controlled`, `external_parameters`).

The base image uses two different signing keys (Red Hat's release3 key for the image signature and Konflux's p02 key for the provenance attestation), so verification requires two steps.

## Usage

Step 1 — Verify the release signature:

```bash
cosign verify \
  --key 1-mild/conforma/cosign-release.pub \
  --insecure-ignore-tlog \
  <BASE_IMAGE_REF>
```

Step 2 — Verify provenance content:

```bash
ec validate image \
  --image <BASE_IMAGE_REF> \
  --policy 1-mild/conforma/policy.yaml \
  --public-key 1-mild/conforma/cosign-provenance.pub \
  --ignore-rekor
```
