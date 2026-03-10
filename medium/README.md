# Medium

**What does it say inside? Can I combine multiple attestations?**

At the medium level, we go beyond presence checks and inspect provenance
*content*:

- Which source repo and branch was used?
- What were the build parameters?
- Can we combine provenance with other attestations (e.g. SBOM)?

Both engines can also produce summary attestations (VSA/SVR) as output,
decoupling "who evaluates" from "who enforces." An admission controller can
check the VSA without re-running verification.

See [conforma/](conforma/) and [ampel/](ampel/) for engine-specific policies
and invocation instructions.
