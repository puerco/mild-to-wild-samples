# Wild: Conforma

Trusted task bundle verification in Tekton provenance using Conforma.

## What This Checks

1. **All task bundles are trusted** -- every task in the Tekton PipelineRun
   provenance references a bundle that is allowed by the `trusted_task_rules`
   configuration

## Why This Matters

Tekton Chains accurately records the tasks that ran in a pipeline. But pipelines are user-customizable -- any task *could* have injected or copied a different artifact. By verifying that every task is allowed by the trusted task rules (and deny rules don't match), we can reason about artifact integrity: a trusted task behaves according to the organization's security policies.

Note: Signature verification is handled by the Conforma CLI before policy evaluation. Policies do not verify signatures.

## Dependencies

This policy requires the Conforma policy library from the `conforma-policy` repository:
- `data.lib` - provides result helpers and Tekton-specific attestation filtering
- `data.lib.tekton` - provides Tekton task helpers including trusted task validation
- `data.lib.rule_data` - provides access to rule_data configuration

## Rule Data Configuration

The policy reads `trusted_task_rules` from rule_data, which contains pattern-based allow/deny rules. Example:

```yaml
# In your ec-policy configuration
sources:
  - data:
      - oci::quay.io/your-org/policy-data:latest
    policy:
      - oci::quay.io/your-org/policies:latest
```

The policy data should contain:

```json
{
  "trusted_task_rules": {
    "allow": [
      {
        "name": "Allow Konflux catalog tasks",
        "pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"
      }
    ],
    "deny": [
      {
        "name": "Deny deprecated buildah versions",
        "pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
        "versions": ["<0.4"],
        "message": "Upgrade to buildah 0.4 or newer"
      }
    ]
  }
}
```

## Running

A sample [`policy.yaml`](policy.yaml) composes all three levels and includes
the trusted task bundle data source:

```bash
ec validate image \
  --image <IMAGE_REF> \
  --policy wild/conforma/policy.yaml
```

The `trusted_task_rules` will be loaded from your configured policy data source.
