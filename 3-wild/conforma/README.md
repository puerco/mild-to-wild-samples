# Wild: Conforma

This policy adds trusted task verification on top of the mild checks. It inspects the Tekton provenance to confirm that every task matches a known reference — either an OCI bundle digest (for PipelineRun provenance via `trusted_task_rules`) or a git commit (for TaskRun provenance via `trusted_task_refs` in `conforma/data/trusted-tasks.yaml`).

When we can identify the tasks that ran, we know the build environment provided the isolation guarantees required for SLSA Build Level 3. If any task reference is untrusted or unrecognized, the rule produces a warning. The presence of that warning tells the verify-and-attest task that L3 cannot be claimed, so it assigns L2 in the VSA instead.

Like medium, verification requires two passes because the base image and built image have different signing keys and builder configurations. The wild policy adds trusted task rules on top.

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

Pass 2 — Verify the built image with the wild [`policy.yaml`](policy.yaml):

```bash
ec validate image \
  --image <BUILT_IMAGE_REF> \
  --policy 3-wild/conforma/policy.yaml \
  --public-key 3-wild/conforma/cosign-chains.pub \
  --ignore-rekor
```
