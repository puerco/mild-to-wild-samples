# Wild: AMPEL

Trusted task bundle verification in Tekton provenance using [AMPEL](https://github.com/carabiner-dev/ampel).

## What This Checks

1. **All task bundles are trusted** -- every task bundle in the
   Tekton provenance starts with the approved prefix

The policy uses a `context` value for the allowed bundle prefix,
making it reusable across environments. The default can be overridden
at evaluation time via `--context-yaml` (see
[carabiner-dev/ampel#207](https://github.com/carabiner-dev/ampel/pull/207)).

## Running

```bash
# Use the default allowed_bundle_prefix from the policy:
ampel verify <IMAGE_REF> \
  --policy ./policy.hjson

# Override the prefix per-environment via a YAML context file:
ampel verify <IMAGE_REF> \
  --policy ./policy.hjson \
  --context-yaml @context.yaml
```

Example `context.yaml`:

```yaml
allowed_bundle_prefix: "quay.io/my-org/tekton-catalog/"
```
