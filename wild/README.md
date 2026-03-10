# Wild

**Did those steps actually produce this artifact?**

At the wild level, we address the deeper trust question: the provenance
records what tasks ran, but did those tasks actually *produce* this artifact?

Tekton Chains accurately records tasks, but pipelines are user-customizable.
Any task could have injected a different artifact. By verifying that every task
used a **pinned, trusted bundle digest**, we close the provenance loop -- a
pinned task behaves deterministically because it was pinned before the build ran.

See [conforma/](conforma/) and [ampel/](ampel/) for engine-specific policies
and invocation instructions.
