package mild

import rego.v1

import data.lib

# METADATA
# title: Provenance attestation present
# description: >-
#   The artifact must have a SLSA provenance attestation (v0.2 or v1) attached.
# custom:
#   short_name: provenance_present
#   failure_msg: No SLSA provenance attestation found
#   solution: >-
#     Ensure the build system produces a SLSA provenance attestation and attaches
#     it to the artifact.
#   collections:
#   - minimal
deny contains result if {
	count(lib.slsa_provenance_attestations) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# Signer identity is verified by the github_certificate package from conforma-policy.
# For GitHub Actions builds, include that package alongside this one to check
# Fulcio certificate extensions (workflow repository, ref, trigger, etc.).
# See: https://github.com/conforma/policy/tree/main/policy/release/github_certificate

# METADATA
# title: VSA meets SLSA Build Level 1
# description: >-
#   A Verification Summary Attestation (VSA) must be present and declare
#   at least SLSA_BUILD_LEVEL_1. VSAs declaring only SLSA_BUILD_LEVEL_0
#   are rejected.
# custom:
#   short_name: vsa_meets_slsa_level
#   failure_msg: VSA does not meet SLSA Build Level 1
#   solution: >-
#     Ensure the build meets SLSA Build Level 1 requirements and the VSA
#     is generated with the appropriate verified levels.
#   collections:
#   - minimal
deny contains result if {
	vsa := input.attestations[_]
	vsa.statement.predicateType == "https://slsa.dev/verification_summary/v1"
	not "SLSA_BUILD_LEVEL_1" in vsa.statement.predicate.verifiedLevels
	result := lib.result_helper(rego.metadata.chain(), [])
}
