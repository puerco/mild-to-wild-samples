# Medium: AMPEL

Content inspection and multi-attestation evaluation using [AMPEL](https://github.com/carabiner-dev/ampel).

## What This Checks

1. **Trusted source branch** -- provenance shows the artifact was built from `refs/heads/main`
2. **SBOM present** -- a CycloneDX SBOM attestation is attached

AMPEL can also produce a VSA (SLSA Verification Summary Attestation) as
output using `--attest-results --attest-format=vsa`, decoupling "who
evaluates" from "who enforces."

## Running

```bash
ampel verify <IMAGE_REF> \
  --policy ./policy.hjson \
  --attest-results \
  --attest-format=vsa
```
