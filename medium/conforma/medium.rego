package medium

import rego.v1

import data.lib
import data.lib.sbom

# METADATA
# title: Source built from trusted branch
# description: >-
#   The provenance must show the artifact was built from the main branch.
# custom:
#   short_name: trusted_source_branch
#   failure_msg: Build not from trusted branch, found %s
#   solution: >-
#     Ensure the artifact is built from refs/heads/main.
#   collections:
#   - minimal
deny contains result if {
	some att in lib.slsa_provenance_attestations
	ref := _git_ref(att)
	not startswith(ref, "refs/heads/main")
	result := lib.result_helper(rego.metadata.chain(), [ref])
}

# METADATA
# title: SBOM attestation present
# description: >-
#   A CycloneDX SBOM attestation must be attached to the artifact.
# custom:
#   short_name: sbom_present
#   failure_msg: No CycloneDX SBOM found
#   solution: >-
#     Ensure the build pipeline generates a CycloneDX SBOM and attaches it
#     as an attestation to the artifact.
#   collections:
#   - minimal
deny contains result if {
	count(sbom.cyclonedx_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# Extract git ref from SLSA v1.0 provenance external parameters
_git_ref(att) := att.statement.predicate.buildDefinition.externalParameters.git.ref
