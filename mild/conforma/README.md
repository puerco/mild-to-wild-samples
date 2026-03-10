# Mild: Conforma

Presence and validity checks using Conforma (Rego-based policy engine).

## What This Checks

1. **Provenance present** -- a SLSA provenance attestation (v0.2 or v1) is attached to the artifact
2. **GitHub certificate identity** -- the image signature's Fulcio certificate contains the expected GitHub Actions workflow extensions (repository, ref, trigger, etc.), via the [`github_certificate`](https://github.com/conforma/policy/tree/main/policy/release/github_certificate) package from conforma-policy
3. **SLSA level** -- a VSA declares at least `SLSA_BUILD_LEVEL_1`; rejects level-0-only VSAs

Note: The Conforma CLI verifies cryptographic signature validity before policy evaluation. The `github_certificate` package checks signer *identity* -- ensuring the right GitHub Actions workflow signed, not just that the signature is valid.

## Dependencies

This policy requires the Conforma policy library from the `conforma-policy` repository:
- `data.lib` - provides result helpers and attestation filtering

## Scenario

An OCI artifact in a registry, built on GitHub Actions with Sigstore signing.
The attestation format is the interface -- these checks work with any
SLSA-capable build system that uses Fulcio certificates.

## Running

A sample [`policy.yaml`](policy.yaml) is provided that composes our custom
rules with the `github_certificate` package. It shows how to configure
allowed workflow repositories and select specific rules:

```bash
ec validate image \
  --image <IMAGE_REF> \
  --policy mild/conforma/policy.yaml
```

See [Conforma CLI documentation](https://github.com/enterprise-contract/ec-cli) for full usage.
