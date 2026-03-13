# From Mild to Wild: How Hot Can Your SLSA Be?

Sample policies for the [From Mild to Wild](https://slides.arewm.com/presentations/2026-03-23-from-mild-to-wild/)
talk at Open Source SecurityCon 2026, demonstrating three levels of SLSA policy
enforcement with two interchangeable policy engines.

## Structure

| Level | What it checks | Directory |
|-------|---------------|-----------|
| **Mild** | Attestation presence, signer identity, SLSA level | [`1-mild/`](1-mild/) |
| **Medium** | Provenance content inspection, multi-attestation evaluation, VSA/SVR production | [`2-medium/`](2-medium/) |
| **Wild** | Trusted task bundle digests in Tekton provenance | [`3-wild/`](3-wild/) |

Each level contains policies for both engines:

- **[Conforma](https://conforma.dev)** -- Rego-based policy engine built around Tekton/Konflux
- **[AMPEL](https://github.com/carabiner-dev/ampel)** -- Policy engine for in-toto attestation evaluation, produces VSAs and SVRs

## Testing (Conforma policies)

The Conforma policies have OPA tests that run with `ec opa test`. The test
runner needs the Conforma CLI and the upstream policy library (which provides
`data.lib` helpers, attestation filtering, Tekton task helpers, etc.).

**Prerequisites:**

1. The [Conforma CLI](https://github.com/enterprise-contract/ec-cli) (`ec`
   binary). Standard `opa` will not work -- the tests depend on `ec`-specific
   OPA extensions.
2. The [Conforma policy library](https://github.com/conforma/policy) cloned
   locally. Tests load `policy/lib/` and `policy/release/lib/` from this repo.

**Running tests:**

The `test_policy.sh` script locates both dependencies via environment variables.
By default it looks for sibling directories named `conforma-cli` and
`conforma-policy`:

```bash
# If repos are sibling directories (the default), just run:
./test_policy.sh

# Otherwise, set paths explicitly:
export CONFORMA_POLICY_PATH=/path/to/conforma-policy
export CONFORMA_CLI_PATH=/path/to/conforma-cli
./test_policy.sh

# Run a specific level:
./test_policy.sh mild
./test_policy.sh medium
./test_policy.sh wild
```

## Build Infrastructure (Wild level)

The `3-wild/` directory includes a sample Tekton Task and Pipeline for building
and pushing container images. These demonstrate the trusted task verification
that the Wild-level policies enforce.

- **Task**: `3-wild/tekton/tasks/build-and-push/0.1/build-and-push.yaml`
- **Pipeline**: `3-wild/tekton/pipelines/build-and-push/0.1/build-and-push.yaml`
- **Trusted refs**: `3-wild/tekton/trusted-tasks.yaml`

The Pipeline uses an inline `taskSpec` for self-contained execution. The
standalone Task definition serves as the canonical reference for git resolver
usage and policy verification.

## Key Takeaway

Policy engines are interchangeable because attestation standards are open
(in-toto, SLSA). Your policies travel with you -- pick the engine that fits
your stack.
