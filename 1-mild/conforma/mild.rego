package mild

import rego.v1

import data.lib

# METADATA
# title: Provenance attestation present
# description: >-
#   The artifact must have a SLSA provenance attestation attached.
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

# METADATA
# title: Build type is accepted
# description: >-
#   The provenance buildDefinition.buildType must be in the list of accepted
#   build types configured via rule_data.allowed_build_types.
# custom:
#   short_name: build_type_accepted
#   failure_msg: "Build type %s is not in the list of accepted build types"
#   solution: >-
#     Ensure the build was performed by an accepted build system. Add the build
#     type to the allowed_build_types rule data if it should be trusted.
#   collections:
#   - minimal
deny contains result if {
	some att in lib.slsa_provenance_attestations
	build_type := _build_type(att)
	allowed := lib.rule_data("allowed_build_types")
	not build_type in allowed
	result := lib.result_helper(rego.metadata.chain(), [build_type])
}

# Extract buildType from either SLSA v0.2 or v1.0
_build_type(att) := att.statement.predicate.buildType if {
	att.statement.predicateType == "https://slsa.dev/provenance/v0.2"
}

_build_type(att) := att.statement.predicate.buildDefinition.buildType if {
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
}
