# Mild

**Is this attestation here? Is it valid?**

At the mild level, we perform presence and validity checks:

- Does the artifact have a SLSA provenance attestation?
- Is it signed by a known builder identity?
- Does a VSA declare at least SLSA Build Level 1?

This is where everyone should start. The attestation format is the interface --
the build system (GitHub Actions, Tekton, etc.) doesn't matter for these checks.

See [conforma/](conforma/) and [ampel/](ampel/) for engine-specific policies
and invocation instructions.
