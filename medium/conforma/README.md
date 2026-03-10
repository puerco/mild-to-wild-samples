# Medium: Conforma

Content inspection of provenance attestations using Conforma.

## What This Checks

1. **Trusted source branch** -- the provenance shows the artifact was built from `refs/heads/main`
2. **SBOM present** -- a CycloneDX SBOM attestation is attached to the artifact

At this level, we go beyond presence checks and inspect the *content* of the provenance. Conforma also produces a verification summary after policy evaluation, which downstream consumers (e.g. admission controllers) can use without re-running verification.

Note: Signature verification is handled by the Conforma CLI before policy evaluation. Policies do not verify signatures.

## Dependencies

This policy requires the Conforma policy library from the `conforma-policy` repository:
- `data.lib` - provides result helpers and Tekton-specific attestation filtering
- `data.lib.sbom` - provides SBOM extraction and validation helpers

See the [attach-vsa task](https://github.com/arewm/slsa-konflux-example/blob/main/managed-context/tasks/attach-vsa/0.1/attach-vsa.yaml) for an example of producing a standard SLSA VSA from Conforma output.

## Running

A sample [`policy.yaml`](policy.yaml) composes mild + medium rules together,
showing how levels build on each other:

```bash
ec validate image \
  --image <IMAGE_REF> \
  --policy medium/conforma/policy.yaml
```
